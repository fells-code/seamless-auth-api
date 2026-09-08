import { beforeEach, describe, expect, it, vi } from 'vitest';

import { findMisusedBearer } from '../../../src/services/bearerRefusal';
import { verifyJwtWithKid } from '../../../src/services/sessionService';

function tokenWithClaims(claims: unknown) {
  const segment = Buffer.from(JSON.stringify(claims)).toString('base64url');

  return `header.${segment}.signature`;
}

describe('findMisusedBearer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('reports a verified token presented at a gate of another type', async () => {
    (verifyJwtWithKid as any).mockResolvedValue({ typ: 'ephemeral', sub: 'user-1' });

    const result = await findMisusedBearer(tokenWithClaims({ typ: 'ephemeral' }), 'access');

    expect(result).toEqual({ presentedType: 'ephemeral', subject: 'user-1' });
  });

  it('reports no subject when the verified token carries none', async () => {
    (verifyJwtWithKid as any).mockResolvedValue({ typ: 'access' });

    const result = await findMisusedBearer(tokenWithClaims({ typ: 'access' }), 'ephemeral');

    expect(result).toEqual({ presentedType: 'access', subject: null });
  });

  it('does not verify a token that claims the type the gate asked for', async () => {
    const result = await findMisusedBearer(tokenWithClaims({ typ: 'access' }), 'access');

    expect(result).toBeNull();
    expect(verifyJwtWithKid).not.toHaveBeenCalled();
  });

  it('ignores a token whose signature does not verify', async () => {
    (verifyJwtWithKid as any).mockResolvedValue(null);

    const result = await findMisusedBearer(tokenWithClaims({ typ: 'ephemeral' }), 'access');

    expect(result).toBeNull();
  });

  it('ignores a verified payload whose type disagrees with the claimed one', async () => {
    (verifyJwtWithKid as any).mockResolvedValue({ typ: 'access', sub: 'user-1' });

    const result = await findMisusedBearer(tokenWithClaims({ typ: 'ephemeral' }), 'access');

    expect(result).toBeNull();
  });

  it('ignores a verified payload with no type at all', async () => {
    (verifyJwtWithKid as any).mockResolvedValue({ sub: 'user-1' });

    const result = await findMisusedBearer(tokenWithClaims({ typ: 'ephemeral' }), 'access');

    expect(result).toBeNull();
  });

  it.each([
    ['no payload segment', 'not-a-jwt'],
    ['an empty payload segment', 'header..signature'],
    ['an undecodable payload segment', 'header.%%%.signature'],
    ['a payload that is not an object', `header.${Buffer.from('"nope"').toString('base64url')}.s`],
    ['a null payload', `header.${Buffer.from('null').toString('base64url')}.s`],
    ['no type claim', tokenWithClaims({ sub: 'user-1' })],
    ['a non-string type claim', tokenWithClaims({ typ: 7 })],
  ])('spends no verification on %s', async (_case, token) => {
    const result = await findMisusedBearer(token, 'access');

    expect(result).toBeNull();
    expect(verifyJwtWithKid).not.toHaveBeenCalled();
  });
});
