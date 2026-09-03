/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { decodeClientDataJSON, generateUserID } from '@simplewebauthn/server/helpers';
import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { SUPPORTED_ALGORITHM_IDS } from '../lib/webauthnAlgorithms.js';
import {
  addConformanceCredential,
  consumeCeremony,
  findConformanceCredential,
  getConformanceUser,
  rememberCeremony,
  upsertConformanceUser,
} from '../services/conformanceStore.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('conformance');

/**
 * The FIDO2 conformance tools speak one envelope for every response: `status`
 * plus `errorMessage`, with the options payload merged in alongside on the
 * options endpoints. A failure is a well-formed body, not a stack trace, which
 * is why nothing here is allowed to fall through to the generic error handler.
 */
function ok(res: Response, payload: Record<string, unknown> = {}) {
  return res.status(200).json({ status: 'ok', errorMessage: '', ...payload });
}

function failed(res: Response, errorMessage: string) {
  return res.status(400).json({ status: 'failed', errorMessage });
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * The challenge the client says it signed.
 *
 * A result request carries no username, so this is what ties it back to the
 * ceremony that issued it. Reading the client's own claim is safe because it is
 * only ever used as a lookup key: the value it finds is the one the server
 * issued, and that stored value is what verification compares against.
 */
function challengeFromResult(body: Record<string, unknown>): string | undefined {
  const response = body?.response as Record<string, unknown> | undefined;
  const clientDataJSON = asString(response?.clientDataJSON);

  if (!clientDataJSON) {
    return undefined;
  }

  try {
    const clientData = decodeClientDataJSON(clientDataJSON);
    return asString(clientData.challenge);
  } catch {
    return undefined;
  }
}

const attestationOptions = async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = asString(body.username);
    const displayName = asString(body.displayName);

    if (!username || !displayName) {
      return failed(res, 'Missing username or displayName');
    }

    const { app_name, rpid } = await getSystemConfig();
    const user = upsertConformanceUser({
      username,
      displayName,
      handle: getConformanceUser(username)?.handle ?? (await generateUserID()),
    });

    // Echoed back rather than replaced by the deployment's authenticator policy.
    // The tools assert that the response carries the selection criteria and
    // attestation conveyance they asked for, and several tests exist purely to
    // vary them.
    const authenticatorSelection = (body.authenticatorSelection ?? {}) as Record<string, unknown>;
    const requestedAttestation = asString(body.attestation) ?? 'none';
    // WebAuthn still defines 'indirect', which SimpleWebAuthn does not accept.
    // It asks for attestation while letting the client anonymize it, so 'direct'
    // is what the server does about it; the requested word is echoed back
    // unchanged because that is what the tools assert on.
    const attestationType = requestedAttestation === 'none' ? 'none' : 'direct';

    const requestedExtensions = asObject(body.extensions);

    const options = await generateRegistrationOptions({
      rpName: app_name,
      rpID: rpid,
      userName: username,
      userDisplayName: displayName,
      userID: user.handle,
      timeout: 60000,
      attestationType,
      supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
      excludeCredentials: user.credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      authenticatorSelection: authenticatorSelection as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      extensions: requestedExtensions as any,
    });

    rememberCeremony({
      purpose: 'registration',
      username,
      challenge: options.challenge,
      requireUserVerification: authenticatorSelection.userVerification === 'required',
    });

    // The tools require the echoed extensions to equal the requested set
    // exactly, and generateRegistrationOptions always appends credProps of its
    // own, so what was asked for is put back over the library's answer.
    return ok(res, {
      ...options,
      ...(requestedExtensions ? { extensions: requestedExtensions } : {}),
      attestation: requestedAttestation,
    });
  } catch (error) {
    logger.error(`Conformance attestation options failed: ${error}`);
    return failed(res, 'Could not generate attestation options');
  }
};

const attestationResult = async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const challenge = challengeFromResult(body);
    const ceremony = challenge ? consumeCeremony(challenge) : undefined;

    if (!ceremony || ceremony.purpose !== 'registration') {
      return failed(res, 'No outstanding registration ceremony for this challenge');
    }

    const { origins, rpid } = await getSystemConfig();

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        response: body as any,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: origins,
        expectedRPID: rpid,
        requireUserVerification: ceremony.requireUserVerification,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
      });
    } catch (error) {
      return failed(
        res,
        error instanceof Error ? error.message : 'Registration verification failed',
      );
    }

    if (!verification.verified || !verification.registrationInfo) {
      return failed(res, 'Registration response could not be verified');
    }

    const { credential } = verification.registrationInfo;

    addConformanceCredential(ceremony.username, {
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports,
    });

    return ok(res);
  } catch (error) {
    logger.error(`Conformance attestation result failed: ${error}`);
    return failed(res, 'Could not process attestation result');
  }
};

const assertionOptions = async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = asString(body.username);
    const userVerification = (asString(body.userVerification) ?? 'preferred') as
      'required' | 'preferred' | 'discouraged';

    // No username means a discoverable-credential ceremony, which the tools also
    // drive. `allowCredentials` is left undefined there so the authenticator
    // chooses, and the result is matched back by credential id.
    const user = username ? getConformanceUser(username) : undefined;

    if (username && !user) {
      return failed(res, 'User does not exist');
    }

    const { rpid } = await getSystemConfig();

    const options = await generateAuthenticationOptions({
      rpID: rpid,
      timeout: 60000,
      userVerification,
      allowCredentials: user
        ? user.credentials.map((credential) => ({
            id: credential.id,
            transports: credential.transports,
          }))
        : undefined,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      extensions: body.extensions as any,
    });

    rememberCeremony({
      purpose: 'authentication',
      username: username ?? '',
      challenge: options.challenge,
      requireUserVerification: userVerification === 'required',
    });

    return ok(res, { ...options });
  } catch (error) {
    logger.error(`Conformance assertion options failed: ${error}`);
    return failed(res, 'Could not generate assertion options');
  }
};

const assertionResult = async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const challenge = challengeFromResult(body);
    const ceremony = challenge ? consumeCeremony(challenge) : undefined;

    if (!ceremony || ceremony.purpose !== 'authentication') {
      return failed(res, 'No outstanding authentication ceremony for this challenge');
    }

    const credentialId = asString(body.id);
    const found = credentialId ? findConformanceCredential(credentialId) : undefined;

    if (!found) {
      return failed(res, 'Credential is not registered');
    }

    // A named ceremony must be answered by that user's credential. Without this
    // an assertion from any enrolled account would satisfy a challenge issued
    // for a different one.
    if (ceremony.username && found.user.username !== ceremony.username) {
      return failed(res, 'Credential does not belong to the requested user');
    }

    const { origins, rpid } = await getSystemConfig();

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        response: body as any,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: origins,
        expectedRPID: rpid,
        requireUserVerification: ceremony.requireUserVerification,
        credential: {
          id: found.credential.id,
          publicKey: found.credential.publicKey,
          counter: found.credential.counter,
          transports: found.credential.transports,
        },
      });
    } catch (error) {
      return failed(
        res,
        error instanceof Error ? error.message : 'Authentication verification failed',
      );
    }

    if (!verification.verified) {
      return failed(res, 'Authentication response could not be verified');
    }

    found.credential.counter = verification.authenticationInfo.newCounter;

    return ok(res);
  } catch (error) {
    logger.error(`Conformance assertion result failed: ${error}`);
    return failed(res, 'Could not process assertion result');
  }
};

export { assertionOptions, assertionResult, attestationOptions, attestationResult };
