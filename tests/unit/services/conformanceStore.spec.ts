import { beforeEach, describe, expect, it } from 'vitest';

import {
  addConformanceCredential,
  consumeCeremony,
  findConformanceCredential,
  getConformanceUser,
  rememberCeremony,
  resetConformanceStore,
  upsertConformanceUser,
} from '../../../src/services/conformanceStore';

const HANDLE = new Uint8Array([1, 2, 3]);

function addUser(username: string) {
  return upsertConformanceUser({ username, displayName: username, handle: HANDLE });
}

function credential(id: string) {
  return { id, publicKey: new Uint8Array([9]), counter: 0 };
}

beforeEach(() => {
  resetConformanceStore();
});

describe('users', () => {
  it('keeps the handle of an existing user and refreshes the display name', () => {
    const first = upsertConformanceUser({ username: 'a@b.c', displayName: 'A', handle: HANDLE });
    const second = upsertConformanceUser({
      username: 'a@b.c',
      displayName: 'Renamed',
      handle: new Uint8Array([4, 5, 6]),
    });

    expect(second).toBe(first);
    expect(second.handle).toBe(HANDLE);
    expect(second.displayName).toBe('Renamed');
  });

  it('reports nothing for a user that was never seen', () => {
    expect(getConformanceUser('nobody@example.com')).toBeUndefined();
  });
});

describe('credentials', () => {
  it('ignores a credential for a user that does not exist', () => {
    addConformanceCredential('ghost@example.com', credential('cred-1'));

    expect(findConformanceCredential('cred-1')).toBeUndefined();
  });

  it('replaces a re-registered credential rather than duplicating it', () => {
    const user = addUser('a@b.c');
    addConformanceCredential('a@b.c', credential('cred-1'));
    addConformanceCredential('a@b.c', { ...credential('cred-1'), counter: 7 });

    expect(user.credentials).toHaveLength(1);
    expect(user.credentials[0].counter).toBe(7);
  });

  it('finds a credential across users, and skips users that do not hold it', () => {
    addUser('first@example.com');
    addUser('second@example.com');
    addConformanceCredential('second@example.com', credential('cred-2'));

    const found = findConformanceCredential('cred-2');

    expect(found?.user.username).toBe('second@example.com');
    expect(found?.credential.id).toBe('cred-2');
  });
});

describe('ceremonies', () => {
  const ceremony = {
    purpose: 'registration' as const,
    username: 'a@b.c',
    challenge: 'challenge-1',
    requireUserVerification: false,
  };

  it('spends a ceremony on the first lookup', () => {
    rememberCeremony(ceremony);

    expect(consumeCeremony('challenge-1')?.username).toBe('a@b.c');
    expect(consumeCeremony('challenge-1')).toBeUndefined();
  });

  it('refuses a ceremony that has passed its expiry', () => {
    const issued = 1_000_000;
    rememberCeremony(ceremony, issued);

    expect(consumeCeremony('challenge-1', issued + 6 * 60 * 1000)).toBeUndefined();
  });

  it('prunes expired ceremonies when a new one is issued', () => {
    const issued = 1_000_000;
    rememberCeremony(ceremony, issued);
    rememberCeremony({ ...ceremony, challenge: 'challenge-2' }, issued + 6 * 60 * 1000);

    // Pruned on issue, so the expired entry is gone before its own expiry is read.
    expect(consumeCeremony('challenge-1', issued)).toBeUndefined();
    expect(consumeCeremony('challenge-2', issued + 6 * 60 * 1000)?.challenge).toBe('challenge-2');
  });

  it('forgets everything on reset', () => {
    addUser('a@b.c');
    rememberCeremony(ceremony);
    resetConformanceStore();

    expect(getConformanceUser('a@b.c')).toBeUndefined();
    expect(consumeCeremony('challenge-1')).toBeUndefined();
  });
});
