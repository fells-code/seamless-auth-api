import express, { Express } from 'express';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { resetConformanceStore } from '../../../src/services/conformanceStore';
import { SoftwareAuthenticator } from '../../factories/softwareAuthenticator';

// The shared setup stubs the WebAuthn library out. This surface exists to be driven
// by a real ceremony, so the real implementation is what has to run here.
vi.unmock('@simplewebauthn/server');

const ORIGIN = 'http://localhost:5137';
const RPID = 'localhost';

async function buildAppWithFlag(value: string | undefined): Promise<Express> {
  const previous = process.env.FIDO_CONFORMANCE_MODE;

  if (value === undefined) delete process.env.FIDO_CONFORMANCE_MODE;
  else process.env.FIDO_CONFORMANCE_MODE = value;

  vi.resetModules();
  const routes = await import('../../../src/routes/conformance.routes');

  if (previous === undefined) delete process.env.FIDO_CONFORMANCE_MODE;
  else process.env.FIDO_CONFORMANCE_MODE = previous;

  const app = express();
  app.use(express.json());
  app.use(routes.default);
  app.use((_req, res) => res.status(404).json({ error: 'Not Found' }));

  return app;
}

const PATHS = [
  '/conformance/attestation/options',
  '/conformance/attestation/result',
  '/conformance/assertion/options',
  '/conformance/assertion/result',
];

beforeEach(() => {
  resetConformanceStore();
  (getSystemConfig as any).mockResolvedValue({
    app_name: 'SeamlessAuth',
    rpid: RPID,
    origins: [ORIGIN],
  });
});

describe('conformance interface mounting', () => {
  it('registers nothing when the flag is unset', async () => {
    const app = await buildAppWithFlag(undefined);

    for (const path of PATHS) {
      const res = await request(app).post(path).send({});
      expect(res.status).toBe(404);
    }
  });

  it('registers nothing when the flag is set under a production NODE_ENV', async () => {
    const nodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    try {
      const app = await buildAppWithFlag('true');

      for (const path of PATHS) {
        const res = await request(app).post(path).send({});
        expect(res.status).toBe(404);
      }
    } finally {
      process.env.NODE_ENV = nodeEnv;
    }
  });

  it('is absent from the application built with the flag unset', async () => {
    const app = await createApp();

    for (const path of PATHS) {
      const res = await request(app).post(path).send({});
      expect(res.status).toBe(404);
    }
  });
});

describe('conformance interface with the flag set', () => {
  let app: Express;

  beforeAll(async () => {
    app = await buildAppWithFlag('true');
  });

  afterAll(() => {
    vi.resetModules();
  });

  describe('POST /conformance/attestation/options', () => {
    it('answers the conformance envelope with the requested criteria echoed back', async () => {
      const res = await request(app)
        .post('/conformance/attestation/options')
        .send({
          username: 'johndoe@example.com',
          displayName: 'John Doe',
          authenticatorSelection: {
            requireResidentKey: false,
            authenticatorAttachment: 'cross-platform',
            userVerification: 'preferred',
          },
          attestation: 'direct',
        });

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.errorMessage).toBe('');
      expect(res.body.rp).toEqual({ name: 'SeamlessAuth', id: RPID });
      expect(res.body.user.name).toBe('johndoe@example.com');
      expect(res.body.user.displayName).toBe('John Doe');
      expect(typeof res.body.challenge).toBe('string');
      expect(res.body.attestation).toBe('direct');
      expect(res.body.authenticatorSelection.authenticatorAttachment).toBe('cross-platform');
      expect(res.body.excludeCredentials).toEqual([]);
    });

    it('echoes the requested extensions exactly, without the library adding its own', async () => {
      const res = await request(app)
        .post('/conformance/attestation/options')
        .send({
          username: 'extensions@example.com',
          displayName: 'Extensions',
          extensions: { 'example.extension.bool': true },
        });

      expect(res.status).toBe(200);
      // The tools compare this for deep equality, so an extra credProps of the
      // library's own fails the check.
      expect(res.body.extensions).toEqual({ 'example.extension.bool': true });
    });

    it('advertises every algorithm the FIDO server requirements demand', async () => {
      const res = await request(app)
        .post('/conformance/attestation/options')
        .send({ username: 'algos@example.com', displayName: 'Algos' });

      expect(res.body.pubKeyCredParams.map((param: any) => param.alg)).toEqual([
        -8, -7, -257, -65535,
      ]);
    });

    it('echoes "indirect" back even though it is served as direct attestation', async () => {
      const res = await request(app).post('/conformance/attestation/options').send({
        username: 'indirect@example.com',
        displayName: 'Indirect',
        attestation: 'indirect',
      });

      expect(res.body.attestation).toBe('indirect');
    });

    it('fails without a username or displayName', async () => {
      const res = await request(app)
        .post('/conformance/attestation/options')
        .send({ username: 'nodisplay@example.com' });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: 'failed',
        errorMessage: 'Missing username or displayName',
      });
    });
  });

  describe('POST /conformance/assertion/options', () => {
    it('fails for a user that was never registered', async () => {
      const res = await request(app)
        .post('/conformance/assertion/options')
        .send({ username: 'nobody@example.com' });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ status: 'failed', errorMessage: 'User does not exist' });
    });

    it('omits allowCredentials when no username is given, for a discoverable ceremony', async () => {
      const res = await request(app).post('/conformance/assertion/options').send({});

      expect(res.status).toBe(200);
      expect(res.body.allowCredentials).toBeUndefined();
      expect(res.body.rpId).toBe(RPID);
    });
  });

  describe('result endpoints', () => {
    it('fails a result whose challenge matches no outstanding ceremony', async () => {
      const res = await request(app)
        .post('/conformance/attestation/result')
        .send({
          id: 'abc',
          type: 'public-key',
          response: {
            clientDataJSON: Buffer.from(
              JSON.stringify({ type: 'webauthn.create', challenge: 'unknown', origin: ORIGIN }),
            ).toString('base64url'),
            attestationObject: 'irrelevant',
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.status).toBe('failed');
      expect(res.body.errorMessage).toMatch(/No outstanding registration ceremony/);
    });

    it('fails a result with unreadable clientDataJSON rather than throwing', async () => {
      const res = await request(app)
        .post('/conformance/assertion/result')
        .send({ id: 'abc', type: 'public-key', response: { clientDataJSON: 'not-json' } });

      expect(res.status).toBe(400);
      expect(res.body.status).toBe('failed');
    });
  });

  describe('a full ceremony', () => {
    it('registers a credential and then authenticates with it', async () => {
      const authenticator = new SoftwareAuthenticator();
      const username = 'roundtrip@example.com';

      const attestationOptions = await request(app)
        .post('/conformance/attestation/options')
        .send({ username, displayName: 'Round Trip' });

      const registration = await request(app)
        .post('/conformance/attestation/result')
        .send(
          authenticator.register({
            challenge: attestationOptions.body.challenge,
            origin: ORIGIN,
            rpId: RPID,
          }),
        );

      expect(registration.status).toBe(200);
      expect(registration.body).toEqual({ status: 'ok', errorMessage: '' });

      const assertionOptions = await request(app)
        .post('/conformance/assertion/options')
        .send({ username, userVerification: 'required' });

      expect(assertionOptions.body.allowCredentials).toEqual([
        { id: authenticator.credentialIdB64, type: 'public-key', transports: ['usb'] },
      ]);

      const assertion = await request(app)
        .post('/conformance/assertion/result')
        .send(
          authenticator.authenticate({
            challenge: assertionOptions.body.challenge,
            origin: ORIGIN,
            rpId: RPID,
          }),
        );

      expect(assertion.status).toBe(200);
      expect(assertion.body).toEqual({ status: 'ok', errorMessage: '' });
    });

    it('lists the registered credential in excludeCredentials on a second registration', async () => {
      const authenticator = new SoftwareAuthenticator();
      const username = 'exclude@example.com';

      const first = await request(app)
        .post('/conformance/attestation/options')
        .send({ username, displayName: 'Exclude' });

      await request(app)
        .post('/conformance/attestation/result')
        .send(
          authenticator.register({
            challenge: first.body.challenge,
            origin: ORIGIN,
            rpId: RPID,
          }),
        );

      const second = await request(app)
        .post('/conformance/attestation/options')
        .send({ username, displayName: 'Exclude' });

      expect(second.body.excludeCredentials).toEqual([
        { id: authenticator.credentialIdB64, type: 'public-key', transports: ['usb'] },
      ]);
      // The user handle survives a re-registration, so the tools see one identity.
      expect(second.body.user.id).toBe(first.body.user.id);
    });

    it('refuses a replayed registration result', async () => {
      const authenticator = new SoftwareAuthenticator();

      const options = await request(app)
        .post('/conformance/attestation/options')
        .send({ username: 'replay@example.com', displayName: 'Replay' });

      const attestation = authenticator.register({
        challenge: options.body.challenge,
        origin: ORIGIN,
        rpId: RPID,
      });

      const first = await request(app).post('/conformance/attestation/result').send(attestation);
      const replay = await request(app).post('/conformance/attestation/result').send(attestation);

      expect(first.status).toBe(200);
      expect(replay.status).toBe(400);
      expect(replay.body.errorMessage).toMatch(/No outstanding registration ceremony/);
    });

    it('refuses an assertion from a credential belonging to another user', async () => {
      const mallory = new SoftwareAuthenticator();
      const victim = new SoftwareAuthenticator();

      for (const [authenticator, username] of [
        [mallory, 'mallory@example.com'],
        [victim, 'victim@example.com'],
      ] as const) {
        const options = await request(app)
          .post('/conformance/attestation/options')
          .send({ username, displayName: username });

        await request(app)
          .post('/conformance/attestation/result')
          .send(
            authenticator.register({
              challenge: options.body.challenge,
              origin: ORIGIN,
              rpId: RPID,
            }),
          );
      }

      const assertionOptions = await request(app)
        .post('/conformance/assertion/options')
        .send({ username: 'victim@example.com' });

      const res = await request(app)
        .post('/conformance/assertion/result')
        .send(
          mallory.authenticate({
            challenge: assertionOptions.body.challenge,
            origin: ORIGIN,
            rpId: RPID,
          }),
        );

      expect(res.status).toBe(400);
      expect(res.body.errorMessage).toBe('Credential does not belong to the requested user');
    });

    it('refuses an assertion signed for the wrong origin', async () => {
      const authenticator = new SoftwareAuthenticator();
      const username = 'origin@example.com';

      const attestationOptions = await request(app)
        .post('/conformance/attestation/options')
        .send({ username, displayName: 'Origin' });

      await request(app)
        .post('/conformance/attestation/result')
        .send(
          authenticator.register({
            challenge: attestationOptions.body.challenge,
            origin: ORIGIN,
            rpId: RPID,
          }),
        );

      const assertionOptions = await request(app)
        .post('/conformance/assertion/options')
        .send({ username });

      const res = await request(app)
        .post('/conformance/assertion/result')
        .send(
          authenticator.authenticate({
            challenge: assertionOptions.body.challenge,
            origin: 'http://evil.example',
            rpId: RPID,
          }),
        );

      expect(res.status).toBe(400);
      expect(res.body.errorMessage).toMatch(/origin/i);
    });
  });
});
