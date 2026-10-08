import { beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  getAdapterManifest,
  registerAdapterRoute,
  resetAdapterManifest,
  tokenInResponse,
} from '../../../src/lib/adapterManifest';

const Message = z.object({ message: z.string() });
const Session = z.object({ sub: z.string(), token: z.string(), ttl: z.number() });
const MaybeToken = z.object({
  message: z.string(),
  token: z.string().optional(),
  delivery: z.object({ kind: z.string() }).optional(),
});

function register(overrides: Partial<Parameters<typeof registerAdapterRoute>[0]>) {
  registerAdapterRoute({
    method: 'post',
    path: '/thing',
    auth: undefined,
    adapter: undefined,
    response: { 200: Message },
    ...overrides,
  });
}

beforeEach(() => {
  resetAdapterManifest();
});

describe('tokenInResponse', () => {
  it('reports a required token', () => {
    expect(tokenInResponse({ 200: Session })).toBe('required');
  });

  it('reports an optional token', () => {
    expect(tokenInResponse({ 200: MaybeToken })).toBe('optional');
  });

  it('reports no token', () => {
    expect(tokenInResponse({ 200: Message })).toBe('none');
    expect(tokenInResponse(undefined)).toBe('none');
  });

  it('looks inside unions, intersections and transforms', () => {
    expect(tokenInResponse({ 200: z.union([Message, Session]) })).toBe('required');
    expect(tokenInResponse({ 200: z.intersection(Message, Session) })).toBe('required');
    expect(tokenInResponse({ 200: Session.transform((value) => value) })).toBe('required');
  });

  it('accepts a bare schema as the 200 response', () => {
    expect(tokenInResponse(Session)).toBe('required');
  });

  it('ignores error responses', () => {
    expect(tokenInResponse({ 200: Message, 401: Session })).toBe('none');
  });
});

describe('registerAdapterRoute', () => {
  it('defaults an access route to an exposed passthrough', () => {
    register({ method: 'get', path: '/users/:id', auth: 'access' });

    expect(getAdapterManifest().routes).toEqual([
      { method: 'GET', path: '/users/{id}', credential: 'access' },
    ]);
  });

  it('refuses a public route that does not say whether adapters expose it', () => {
    expect(() => register({})).toThrow(/declares no adapter behaviour/);
  });

  it('leaves a route marked false out of the manifest', () => {
    register({ adapter: false });
    register({ auth: 'access', adapter: false, response: { 200: Session } });

    expect(getAdapterManifest().routes).toEqual([]);
  });

  it('refuses an ephemeral route with no credential', () => {
    expect(() => register({ auth: 'ephemeral', adapter: {} })).toThrow(
      /declares no adapter credential/,
    );
  });

  it.each([
    ['access', 'preAuth'],
    ['ephemeral', 'access'],
    [undefined, 'access'],
    [undefined, 'registration'],
  ] as const)('refuses a %s route that sends the %s credential', (auth, credential) => {
    expect(() => register({ auth, adapter: { credential } })).toThrow(
      /cannot use adapter credential/,
    );
  });

  it('refuses a route that always returns a token but issues nothing', () => {
    expect(() => register({ auth: 'access', response: { 200: Session } })).toThrow(
      /returns a token but declares no adapter `issues`/,
    );
  });

  it('allows a route whose token is optional to issue nothing', () => {
    expect(() =>
      register({
        auth: 'ephemeral',
        adapter: { credential: 'preAuth' },
        response: { 200: MaybeToken },
      }),
    ).not.toThrow();
  });

  it('refuses issues on a route with no token in its response', () => {
    expect(() => register({ adapter: { issues: 'session' } })).toThrow(
      /no success response schema has a token/,
    );
  });

  it('refuses delivery on a route whose response cannot carry a delivery payload', () => {
    expect(() => register({ auth: 'access', adapter: { delivery: true } })).toThrow(
      /no success response has a delivery payload/,
    );
  });

  it('refuses a body pick on a route that issues nothing', () => {
    expect(() => register({ adapter: { body: { pick: ['message'] } } })).toThrow(/issues nothing/);
  });

  it('records every declared field', () => {
    register({
      path: '/login/',
      adapter: { issues: 'preAuth', body: { pick: ['message'] } },
      response: { 200: MaybeToken },
    });
    register({
      method: 'delete',
      path: '/logout',
      auth: 'access',
      adapter: { clears: ['access', 'refresh'] },
    });
    register({
      path: '/send',
      auth: 'ephemeral',
      adapter: { credential: 'registration', delivery: true },
      response: { 200: MaybeToken },
    });

    expect(getAdapterManifest().routes).toEqual([
      {
        method: 'POST',
        path: '/login',
        credential: 'none',
        issues: 'preAuth',
        body: { pick: ['message'] },
      },
      { method: 'DELETE', path: '/logout', credential: 'access', clears: ['access', 'refresh'] },
      { method: 'POST', path: '/send', credential: 'registration', delivery: true },
    ]);
  });

  it('keeps one entry per method and path when a route is registered again', () => {
    register({ auth: 'access' });
    register({ auth: 'access' });

    expect(getAdapterManifest().routes).toHaveLength(1);
  });
});
