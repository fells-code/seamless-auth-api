import { QueryTypes } from 'sequelize';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { getSequelize, initializeModels } from '../../src/models/index.js';
import { sealAuditChainHead, verifyAuthEventChain } from '../../src/services/auditIntegrity.js';
import { AuthEventService } from '../../src/services/authEventService.js';

const KEY = 'audit-chain-head-test-key';

type Head = {
  seq: string;
  last_hash: string | null;
  signed_seq: string | null;
  signature: string | null;
};

async function head() {
  const [row] = await getSequelize().query<Head>(
    'SELECT seq, last_hash, signed_seq, signature FROM auth_event_chain_head WHERE id = 1',
    { type: QueryTypes.SELECT },
  );
  return row;
}

async function logEvents(count: number) {
  await Promise.all(
    Array.from({ length: count }, (_, index) =>
      AuthEventService.logContext({ type: 'login_success', metadata: { index } }),
    ),
  );
}

async function hashAt(seq: number) {
  const [row] = await getSequelize().query<{ hash: string }>(
    'SELECT hash FROM auth_events WHERE seq = :seq',
    { replacements: { seq }, type: QueryTypes.SELECT },
  );
  return row.hash;
}

async function withGuardDisabled(fn: () => Promise<unknown>) {
  const sequelize = getSequelize();
  await sequelize.query(
    'ALTER TABLE auth_event_chain_head DISABLE TRIGGER auth_event_chain_head_guard',
  );
  try {
    await fn();
  } finally {
    await sequelize.query(
      'ALTER TABLE auth_event_chain_head ENABLE TRIGGER auth_event_chain_head_guard',
    );
  }
}

// The steps from the review: retention's setting is open to any session, so DELETE the
// newest rows under it, then move the head back to the last row left.
async function truncateTail(keep: number) {
  await getSequelize().transaction(async (transaction) => {
    await getSequelize().query("SET LOCAL seamless.audit_retention = 'on'", { transaction });
    await getSequelize().query('DELETE FROM auth_events WHERE seq > :keep', {
      replacements: { keep },
      transaction,
    });
  });
}

beforeAll(async () => {
  await initializeModels();
});

afterEach(() => {
  delete process.env.AUDIT_CHAIN_KEY;
});

afterAll(async () => {
  await getSequelize().close();
});

describe('auth_event_chain_head guard', () => {
  it.each([
    ['UPDATE seq', 'UPDATE auth_event_chain_head SET seq = seq - 1'],
    ['UPDATE last_hash', "UPDATE auth_event_chain_head SET last_hash = repeat('0', 64)"],
    ['INSERT', 'INSERT INTO auth_event_chain_head (id, seq) VALUES (2, 0)'],
    ['DELETE', 'DELETE FROM auth_event_chain_head'],
    ['TRUNCATE', 'TRUNCATE auth_event_chain_head'],
  ])('refuses %s', async (_op, sql) => {
    await logEvents(1);

    await expect(getSequelize().query(sql)).rejects.toThrow(/auth_event_chain_head/);
  });

  it('refuses re-heading a truncated tail, so the truncation is reported', async () => {
    await logEvents(3);
    const { seq } = await head();
    const keep = Number(seq) - 2;
    const keptHash = await hashAt(keep);

    await truncateTail(keep);

    await expect(
      getSequelize().query(
        'UPDATE auth_event_chain_head SET seq = :keep, last_hash = :keptHash WHERE id = 1',
        { replacements: { keep, keptHash } },
      ),
    ).rejects.toThrow(/only moves when an event is inserted/);

    expect((await verifyAuthEventChain()).firstFailure).toMatchObject({
      reason: 'head_mismatch',
    });

    // Leaves the shared database verifying for the files that run after this one.
    await withGuardDisabled(() =>
      getSequelize().query(
        'UPDATE auth_event_chain_head SET seq = :keep, last_hash = :keptHash WHERE id = 1',
        { replacements: { keep, keptHash } },
      ),
    );
  });

  it('still lets the insert trigger advance the head', async () => {
    const before = Number((await head()).seq);

    await logEvents(5);

    expect(Number((await head()).seq)).toBe(before + 5);
    expect((await verifyAuthEventChain()).verified).toBe(true);
  });
});

describe('signed chain head', () => {
  it('reports an unsigned head as a failure once the key is set, and seals it', async () => {
    process.env.AUDIT_CHAIN_KEY = KEY;

    const unsigned = await verifyAuthEventChain();
    expect(unsigned).toMatchObject({ verified: false, headSigned: false });
    expect(unsigned.firstFailure?.reason).toBe('head_unsigned');

    const sealed = await sealAuditChainHead();
    const report = await verifyAuthEventChain();

    expect(report).toMatchObject({ verified: true, headSigned: true });
    expect(report.head).toEqual(sealed);
  });

  it('carries the signature forward across concurrent inserts', async () => {
    process.env.AUDIT_CHAIN_KEY = KEY;
    await sealAuditChainHead();

    await logEvents(15);

    const current = await head();
    expect(current.signed_seq).toBe(current.seq);
    expect(await verifyAuthEventChain()).toMatchObject({ verified: true, headSigned: true });
  });

  it('catches up after an insert made without the key', async () => {
    process.env.AUDIT_CHAIN_KEY = KEY;
    await sealAuditChainHead();

    delete process.env.AUDIT_CHAIN_KEY;
    await logEvents(1);
    process.env.AUDIT_CHAIN_KEY = KEY;

    expect((await verifyAuthEventChain()).firstFailure?.reason).toBe('head_unsigned');

    await logEvents(1);

    expect(await verifyAuthEventChain()).toMatchObject({ verified: true, headSigned: true });
  });

  it('reports a head re-pointed past the trigger, even with the signature moved too', async () => {
    process.env.AUDIT_CHAIN_KEY = KEY;
    await sealAuditChainHead();
    await logEvents(3);
    const { seq, signature } = await head();
    const keep = Number(seq) - 2;
    const keptHash = await hashAt(keep);

    await truncateTail(keep);
    await withGuardDisabled(() =>
      getSequelize().query(
        `UPDATE auth_event_chain_head
           SET seq = :keep, last_hash = :keptHash, signed_seq = :keep, signature = :signature
           WHERE id = 1`,
        { replacements: { keep, keptHash, signature } },
      ),
    );

    expect((await verifyAuthEventChain()).firstFailure).toMatchObject({
      reason: 'head_mismatch',
    });

    // Signing forward from a signature that does not verify would hide the tampering.
    await logEvents(1);

    expect(await verifyAuthEventChain()).toMatchObject({ verified: false, headSigned: false });

    await sealAuditChainHead();
  });

  it('refuses clearing the signature or moving it backwards', async () => {
    process.env.AUDIT_CHAIN_KEY = KEY;
    await sealAuditChainHead();

    await expect(
      getSequelize().query('UPDATE auth_event_chain_head SET signature = NULL, signed_seq = NULL'),
    ).rejects.toThrow(/only move forward/);
    await expect(
      getSequelize().query('UPDATE auth_event_chain_head SET signed_seq = signed_seq - 1'),
    ).rejects.toThrow(/only move forward/);
  });

  it('refuses to seal a chain that does not verify', async () => {
    process.env.AUDIT_CHAIN_KEY = KEY;
    await logEvents(1);
    const { seq, last_hash: lastHash } = await head();
    const sequelize = getSequelize();

    await sequelize.query('ALTER TABLE auth_events DISABLE TRIGGER auth_events_append_only');
    try {
      await sequelize.query(`UPDATE auth_events SET metadata = '{"index":99}' WHERE seq = :seq`, {
        replacements: { seq },
      });

      await expect(sealAuditChainHead()).rejects.toThrow(/does not verify \(hash_mismatch/);

      await sequelize.query(`UPDATE auth_events SET metadata = '{"index":0}' WHERE seq = :seq`, {
        replacements: { seq },
      });
    } finally {
      await sequelize.query('ALTER TABLE auth_events ENABLE TRIGGER auth_events_append_only');
    }

    expect((await head()).last_hash).toBe(lastHash);
  });
});
