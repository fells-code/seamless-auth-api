import { isoCBOR } from '@simplewebauthn/server/helpers';
import crypto from 'crypto';

/**
 * A minimal ES256 authenticator, enough to drive a real ceremony end to end.
 *
 * `fmt: 'none'` only, which is the shape the conformance interface has to get
 * right before any attestation format matters. Real attestation statements come
 * from the conformance tools and are covered separately.
 */
export class SoftwareAuthenticator {
  readonly credentialId: Uint8Array;
  private readonly privateKey: crypto.KeyObject;
  private readonly publicKey: crypto.KeyObject;
  private counter = 0;

  constructor(credentialId = crypto.randomBytes(32)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    this.credentialId = new Uint8Array(credentialId);
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  get credentialIdB64() {
    return Buffer.from(this.credentialId).toString('base64url');
  }

  register(params: { challenge: string; origin: string; rpId: string }) {
    const clientDataJSON = buildClientData('webauthn.create', params.challenge, params.origin);
    const authData = this.buildAuthData(params.rpId, true);

    const attestationObject = isoCBOR.encode(
      new Map<string, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]) as never,
    );

    return {
      id: this.credentialIdB64,
      rawId: this.credentialIdB64,
      type: 'public-key',
      clientExtensionResults: {},
      getClientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        attestationObject: b64u(attestationObject),
        transports: ['usb'],
      },
    };
  }

  authenticate(params: { challenge: string; origin: string; rpId: string }) {
    const clientDataJSON = buildClientData('webauthn.get', params.challenge, params.origin);
    const authData = this.buildAuthData(params.rpId, false);
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const signature = crypto.sign(
      'sha256',
      Buffer.concat([Buffer.from(authData), clientDataHash]),
      this.privateKey,
    );

    return {
      id: this.credentialIdB64,
      rawId: this.credentialIdB64,
      type: 'public-key',
      clientExtensionResults: {},
      getClientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: '',
      },
    };
  }

  private buildAuthData(rpId: string, includeAttestedData: boolean) {
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    // UP | UV, plus AT when attested credential data follows.
    const flags = Buffer.from([includeAttestedData ? 0x45 : 0x05]);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(++this.counter);

    if (!includeAttestedData) {
      return new Uint8Array(Buffer.concat([rpIdHash, flags, counter]));
    }

    const credentialIdLength = Buffer.alloc(2);
    credentialIdLength.writeUInt16BE(this.credentialId.length);

    return new Uint8Array(
      Buffer.concat([
        rpIdHash,
        flags,
        counter,
        Buffer.alloc(16), // AAGUID: all zeroes, as an unattested authenticator reports
        credentialIdLength,
        Buffer.from(this.credentialId),
        Buffer.from(this.cosePublicKey()),
      ]),
    );
  }

  private cosePublicKey() {
    const jwk = this.publicKey.export({ format: 'jwk' }) as { x: string; y: string };

    return isoCBOR.encode(
      new Map<number, unknown>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, new Uint8Array(Buffer.from(jwk.x, 'base64url'))],
        [-3, new Uint8Array(Buffer.from(jwk.y, 'base64url'))],
      ]) as never,
    );
  }
}

function buildClientData(type: string, challenge: string, origin: string) {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

function b64u(value: Uint8Array | Buffer) {
  return Buffer.from(value).toString('base64url');
}
