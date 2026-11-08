/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { connect as netConnect, isIP, type Socket } from 'node:net';
import { hostname as osHostname } from 'node:os';
import { connect as tlsConnect } from 'node:tls';

import type {
  CalloutFailure,
  CalloutTestResponse,
  OtlpSinkSettings,
  SyslogSinkSettings,
} from '@seamless-auth/types';
import { AUDIT_SINK_SECRET_ENV_PATTERN } from '@seamless-auth/types';

import { type ExportedAuthEvent, exportLine } from '../services/auditExport.js';
import { authEventOutcome } from './authEventCategories.js';
import {
  CalloutError,
  calloutHostProblem,
  calloutLookup,
  calloutRequest,
  calloutUrlProblem,
} from './calloutTransport.js';

type EnvSource = Record<string, string | undefined>;

export const AUDIT_SINK_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

/**
 * The structured data element carrying `seq` and `hash` in each syslog record. RFC 5424 needs
 * a private SD-ID to be `name@<IANA enterprise number>`. 32473 is the number RFC 5612 reserves
 * for documentation, a placeholder until Fells Code has its own.
 */
// TODO(#586): replace 32473 with the Fells Code IANA enterprise number before release.
export const SYSLOG_SD_ID = 'seamless@32473';

/**
 * Collectors key their parsing rules on the SD-ID, so changing it once adopters have written
 * those rules is a breaking change. Syslog sinks stay refused until the real number is in.
 */
// TODO(#586): set to true in 0.23.1 together with the real SD-ID.
export const SYSLOG_SINKS_AVAILABLE = false;

export const SYSLOG_UNAVAILABLE =
  'Syslog audit sinks are not available in this release; they arrive in Seamless Auth 0.23.1. Use an OTLP sink until then.';

export const AUDIT_SINK_SCOPE = 'seamless-auth.audit';

/**
 * One record for a sink. `event` is null for a test record, which is not part of the chain and
 * carries no `seq` or `hash`, so nothing downstream can mistake it for an event.
 */
export type SinkRecord = { line: string; at: Date; event: ExportedAuthEvent | null };

export type SinkAttempt = CalloutTestResponse;

export function eventRecord(event: ExportedAuthEvent): SinkRecord {
  return { line: exportLine(event), at: new Date(event.createdAt), event };
}

export function testRecord(sinkId: string, at: Date = new Date()): SinkRecord {
  return {
    line: JSON.stringify({ type: 'test', test: true, sinkId, generatedAt: at.toISOString() }),
    at,
    event: null,
  };
}

/** Thrown before any connection for a sink whose settings or env cannot be used. */
class SinkMisconfigured extends CalloutError {
  constructor(message: string) {
    super('misconfigured', message);
  }
}

function isProduction(env: EnvSource) {
  return env.NODE_ENV === 'production';
}

const HOST_NAME =
  /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

type DestinationProblem = { problem: string; failure: 'refused' | 'misconfigured' };

function destinationProblem(
  settings: OtlpSinkSettings | SyslogSinkSettings,
  env: EnvSource,
): DestinationProblem | null {
  if (settings.kind === 'otlp') {
    const problem = calloutUrlProblem(settings.endpoint, env);
    return problem ? { problem: `endpoint ${problem}`, failure: 'refused' } : null;
  }

  const misconfigured = (problem: string): DestinationProblem => ({
    problem,
    failure: 'misconfigured',
  });
  if (!isIP(settings.host) && !HOST_NAME.test(settings.host)) {
    return misconfigured('host is not a host name');
  }
  if (settings.transport === 'tcp' && isProduction(env)) {
    return misconfigured('transport must be tls in production');
  }
  if (Boolean(settings.tlsClientCertEnv) !== Boolean(settings.tlsClientKeyEnv)) {
    return misconfigured('tlsClientCertEnv and tlsClientKeyEnv must be set together');
  }

  const problem = calloutHostProblem(settings.host, env);
  return problem ? { problem: `host ${problem}`, failure: 'refused' } : null;
}

/** What is wrong with a sink's destination, checked when written and again before each send. */
export function sinkDestinationProblem(
  settings: OtlpSinkSettings | SyslogSinkSettings,
  env: EnvSource = process.env,
): string | null {
  return destinationProblem(settings, env)?.problem ?? null;
}

function secretFromEnv(name: string, env: EnvSource): string {
  // The schema already holds names to the pattern; checked again so nothing that bypasses it
  // can read a secret the server keeps for something else.
  if (!AUDIT_SINK_SECRET_ENV_PATTERN.test(name))
    throw new SinkMisconfigured(`${name} is not allowed`);
  const value = env[name];
  if (!value) throw new SinkMisconfigured(`${name} is not set`);
  return value;
}

// The characters Node accepts in a header value. Anything else would throw inside the request.
const HEADER_VALUE = /^[\t\x20-\x7e\x80-\xff]+$/;

function otlpHeaders(settings: OtlpSinkSettings, env: EnvSource) {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  for (const [name, envName] of Object.entries(settings.headersFromEnv)) {
    const value = secretFromEnv(envName, env);
    if (!HEADER_VALUE.test(value)) throw new SinkMisconfigured(`${envName} is not a header value`);
    headers[name] = value;
  }
  return headers;
}

export function otlpLogsUrl(endpoint: string): string {
  const url = new URL(endpoint);
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/v1/logs`;
  return url.toString();
}

type OtlpValue = { stringValue: string } | { intValue: string } | { boolValue: boolean };

function attribute(
  key: string,
  value: string | number | boolean,
): { key: string; value: OtlpValue } {
  if (typeof value === 'boolean') return { key, value: { boolValue: value } };
  if (typeof value === 'number') return { key, value: { intValue: String(value) } };
  return { key, value: { stringValue: value } };
}

function suspicious(record: SinkRecord) {
  return record.event !== null && authEventOutcome(record.event.type) === 'suspicious';
}

function otlpAttributes(record: SinkRecord) {
  const { event } = record;
  if (!event) return [attribute('seamless.audit.test', true)];

  const attributes = [
    attribute('seamless.audit.seq', event.seq),
    attribute('seamless.audit.id', event.id),
    attribute('seamless.audit.type', event.type),
    attribute('seamless.audit.hash', event.hash),
  ];
  if (event.prevHash) attributes.push(attribute('seamless.audit.prev_hash', event.prevHash));
  if (event.userId) attributes.push(attribute('user.id', event.userId));
  if (event.actorUserId)
    attributes.push(attribute('seamless.audit.actor_user_id', event.actorUserId));
  if (event.sessionId) attributes.push(attribute('session.id', event.sessionId));
  return attributes;
}

function unixNano(at: Date) {
  return `${BigInt(at.getTime()) * 1_000_000n}`;
}

/** An OTLP/HTTP JSON `ExportLogsServiceRequest`, one log record per audit event. */
export function otlpLogsBody(records: SinkRecord[], serviceName: string, observed = new Date()) {
  return JSON.stringify({
    resourceLogs: [
      {
        resource: { attributes: [attribute('service.name', serviceName)] },
        scopeLogs: [
          {
            scope: { name: AUDIT_SINK_SCOPE },
            logRecords: records.map((record) => ({
              timeUnixNano: unixNano(record.at),
              observedTimeUnixNano: unixNano(observed),
              severityNumber: suspicious(record) ? 13 : 9,
              severityText: suspicious(record) ? 'WARN' : 'INFO',
              body: { stringValue: record.line },
              attributes: otlpAttributes(record),
            })),
          },
        ],
      },
    ],
  });
}

function sdValue(value: string) {
  return value.replace(/["\\\]]/g, (char) => `\\${char}`);
}

function syslogHostname() {
  const name = osHostname()
    .replace(/[^!-~]/g, '')
    .slice(0, 255);
  return name || '-';
}

/**
 * One RFC 5424 message. MSG is the export line with no BOM: RFC 5424 allows MSG as any octets
 * (MSG-ANY), and a BOM would make the line fail to parse as JSON in most consumers.
 */
export function syslogMessage(
  record: SinkRecord,
  settings: SyslogSinkSettings,
  hostname: string = syslogHostname(),
): string {
  // Informational, or warning for a suspicious event.
  const severity = suspicious(record) ? 4 : 6;
  const pri = settings.facility * 8 + severity;
  const sd = record.event
    ? `[${SYSLOG_SD_ID} seq="${record.event.seq}" hash="${sdValue(record.event.hash)}"]`
    : `[${SYSLOG_SD_ID} test="true"]`;
  const msgId = record.event ? 'audit' : 'test';

  return `<${pri}>1 ${record.at.toISOString()} ${hostname} ${settings.appName} - ${msgId} ${sd} ${record.line}`;
}

/** Octet-counting framing (RFC 6587, 3.4.1), the framing RFC 5425 requires over TLS. */
export function octetFrame(message: string): string {
  return `${Buffer.byteLength(message, 'utf8')} ${message}`;
}

function failureOf(error: unknown): CalloutFailure {
  return error instanceof CalloutError ? error.failure : 'connection_failed';
}

function tlsMaterial(settings: SyslogSinkSettings, env: EnvSource) {
  return {
    ...(settings.tlsCaEnv ? { ca: secretFromEnv(settings.tlsCaEnv, env) } : {}),
    ...(settings.tlsClientCertEnv ? { cert: secretFromEnv(settings.tlsClientCertEnv, env) } : {}),
    ...(settings.tlsClientKeyEnv ? { key: secretFromEnv(settings.tlsClientKeyEnv, env) } : {}),
  };
}

/**
 * Writes every frame on one connection, ends it, and resolves once the collector closes its
 * side. Syslog has no acknowledgement, so that is as much as a sender can know.
 */
function writeSyslog(
  settings: SyslogSinkSettings,
  payload: string,
  env: EnvSource,
  timeoutMs: number,
): Promise<void> {
  const destination = destinationProblem(settings, env);
  if (destination) {
    return Promise.reject(
      new CalloutError(destination.failure, `Audit sink ${destination.problem}`),
    );
  }

  let material: ReturnType<typeof tlsMaterial>;
  try {
    material = tlsMaterial(settings, env);
  } catch (error) {
    return Promise.reject(error);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error: CalloutError | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };

    const send = () => socket.end(payload);
    const lookup = calloutLookup(env);
    const socket: Socket =
      settings.transport === 'tls'
        ? tlsConnect(
            {
              host: settings.host,
              port: settings.port,
              lookup,
              minVersion: 'TLSv1.2',
              ...(isIP(settings.host) ? {} : { servername: settings.host }),
              ...material,
            },
            send,
          )
        : netConnect({ host: settings.host, port: settings.port, lookup }, send);

    const timer = setTimeout(
      () => finish(new CalloutError('timed_out', 'Audit sink timed out')),
      timeoutMs,
    );
    timer.unref();

    // Success is the collector closing its side after reading to our end of stream, which
    // also catches a TLS 1.3 client certificate refused after the client thinks it is done.
    // Anything it sends is discarded, so that close is seen.
    let flushed = false;
    socket.resume();
    socket.on('finish', () => (flushed = true));
    socket.on('close', () =>
      finish(
        flushed ? null : new CalloutError('connection_failed', 'Audit sink connection closed'),
      ),
    );
    socket.on('error', (error: Error) =>
      finish(
        error instanceof CalloutError
          ? error
          : new CalloutError('connection_failed', 'Audit sink connection failed'),
      ),
    );
  });
}

async function sendOtlp(
  settings: OtlpSinkSettings,
  records: SinkRecord[],
  env: EnvSource,
  timeoutMs: number,
): Promise<{ statusCode: number | null; ok: boolean }> {
  const headers = otlpHeaders(settings, env);
  const response = await calloutRequest(
    otlpLogsUrl(settings.endpoint),
    {
      method: 'POST',
      headers,
      body: otlpLogsBody(records, settings.serviceName),
      timeoutMs,
      maxResponseBytes: MAX_RESPONSE_BYTES,
    },
    env,
  );
  return { statusCode: response.status, ok: response.status >= 200 && response.status < 300 };
}

/**
 * Sends records to a sink in order. For OTLP anything but a 2xx is a failure, including a
 * redirect, which is not followed.
 */
export async function sendToSink(
  settings: OtlpSinkSettings | SyslogSinkSettings,
  records: SinkRecord[],
  env: EnvSource = process.env,
  timeoutMs: number = AUDIT_SINK_TIMEOUT_MS,
): Promise<SinkAttempt> {
  const started = Date.now();
  const durationMs = () => Date.now() - started;

  try {
    if (settings.kind === 'otlp') {
      const { statusCode, ok } = await sendOtlp(settings, records, env, timeoutMs);
      return { ok, statusCode, failure: ok ? null : 'http_status', durationMs: durationMs() };
    }

    const hostname = syslogHostname();
    await writeSyslog(
      settings,
      records.map((record) => octetFrame(syslogMessage(record, settings, hostname))).join(''),
      env,
      timeoutMs,
    );
    return { ok: true, statusCode: null, failure: null, durationMs: durationMs() };
  } catch (error) {
    return { ok: false, statusCode: null, failure: failureOf(error), durationMs: durationMs() };
  }
}
