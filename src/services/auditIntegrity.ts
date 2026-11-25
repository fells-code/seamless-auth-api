/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes, Transaction } from 'sequelize';

import { getSequelize } from '../models/index.js';
import { auditChainKey, auditHeadSignatureValid, signAuditHead } from './auditHeadSignature.js';

export type ChainFailureReason =
  'hash_mismatch' | 'broken_link' | 'sequence_gap' | 'head_mismatch' | 'head_unsigned';

export interface AuditIntegrityReport {
  verified: boolean;
  checkedAt: string;
  rowsChecked: number;
  firstSeq: number | null;
  lastSeq: number | null;
  /** The `prev_hash` of the oldest remaining row: the last hash retention archived away. */
  anchorHash: string | null;
  head: { seq: number; hash: string | null } | null;
  /** Whether the head carries a valid `AUDIT_CHAIN_KEY` signature. Always false without the key. */
  headSigned: boolean;
  firstFailure: { seq: number; id: string | null; reason: ChainFailureReason } | null;
}

type ChainRow = {
  rows_checked: string;
  first_seq: string | null;
  last_seq: string | null;
  last_hash: string | null;
  anchor_hash: string | null;
  first_failure: {
    seq: string;
    id: string;
    reason: Exclude<ChainFailureReason, 'head_mismatch' | 'head_unsigned'>;
  } | null;
  head: {
    seq: string;
    hash: string | null;
    signed_seq: string | null;
    signature: string | null;
    signed_hash: string | null;
  } | null;
};

// The expected hash is recomputed with the same database functions the insert trigger
// uses, so the two cannot disagree about what a row's canonical form is.
const VERIFY_CHAIN_SQL = `
  WITH chained AS (
    SELECT
      e.seq,
      e.id,
      e.hash,
      e.prev_hash,
      public.auth_event_hash(e.prev_hash, public.auth_event_payload(e.*)) AS expected,
      lag(e.hash) OVER (ORDER BY e.seq) AS prior_hash,
      lag(e.seq) OVER (ORDER BY e.seq) AS prior_seq
    FROM public.auth_events e
  )
  SELECT
    (SELECT count(*) FROM chained) AS rows_checked,
    (SELECT min(seq) FROM chained) AS first_seq,
    (SELECT max(seq) FROM chained) AS last_seq,
    (SELECT hash FROM chained ORDER BY seq DESC LIMIT 1) AS last_hash,
    (SELECT prev_hash FROM chained ORDER BY seq ASC LIMIT 1) AS anchor_hash,
    (
      SELECT row_to_json(f) FROM (
        SELECT
          seq,
          id,
          CASE
            WHEN hash IS DISTINCT FROM expected THEN 'hash_mismatch'
            WHEN seq <> prior_seq + 1 THEN 'sequence_gap'
            ELSE 'broken_link'
          END AS reason
        FROM chained
        WHERE hash IS DISTINCT FROM expected
          OR (
            prior_seq IS NOT NULL
            AND (seq <> prior_seq + 1 OR prev_hash IS DISTINCT FROM prior_hash)
          )
        ORDER BY seq
        LIMIT 1
      ) f
    ) AS first_failure,
    (
      SELECT row_to_json(h) FROM (
        SELECT h.seq, h.last_hash AS hash, h.signed_seq, h.signature, s.hash AS signed_hash
        FROM public.auth_event_chain_head h
        LEFT JOIN public.auth_events s ON s.seq = h.signed_seq
        WHERE h.id = 1
      ) h
    ) AS head
`;

const toNumber = (value: string | null) => (value === null ? null : Number(value));

type HeadSignature = 'valid' | 'invalid' | 'unsigned' | 'stale';

function headSignature(key: string, head: NonNullable<ChainRow['head']>): HeadSignature {
  if (head.signature === null || head.signed_seq === null) return 'unsigned';

  const signedSeq = Number(head.signed_seq);
  if (!auditHeadSignatureValid(key, signedSeq, head.signed_hash, head.signature)) {
    return 'invalid';
  }

  return signedSeq === Number(head.seq) ? 'valid' : 'stale';
}

async function inspectChain(transaction?: Transaction) {
  const [row] = await getSequelize().query<ChainRow>(VERIFY_CHAIN_SQL, {
    type: QueryTypes.SELECT,
    transaction,
  });

  const head = row.head ? { seq: Number(row.head.seq), hash: row.head.hash } : null;
  const lastSeq = toNumber(row.last_seq);

  let chainFailure: AuditIntegrityReport['firstFailure'] = row.first_failure
    ? {
        seq: Number(row.first_failure.seq),
        id: row.first_failure.id,
        reason: row.first_failure.reason,
      }
    : null;

  const headMatches =
    head !== null && head.seq === (lastSeq ?? head.seq) && head.hash === row.last_hash;

  if (!chainFailure && !headMatches) {
    chainFailure = { seq: head?.seq ?? lastSeq ?? 0, id: null, reason: 'head_mismatch' };
  }

  return { row, head, lastSeq, chainFailure };
}

/**
 * Walks the whole audit chain and reports the first place it does not hold.
 *
 * A row whose content changed fails its own hash. A row removed from the middle leaves a
 * gap in `seq`. Rows removed from the end leave the chain head ahead of the newest row.
 * With `AUDIT_CHAIN_KEY` set, the head must also carry a signature made with it, so a
 * head moved back over a truncated tail, which the database alone would accept, fails.
 * Rewriting the entire chain consistently is not detectable from inside the database,
 * which is why the head this returns is worth recording somewhere else.
 */
export async function verifyAuthEventChain(): Promise<AuditIntegrityReport> {
  const { row, head, lastSeq, chainFailure } = await inspectChain();
  const key = auditChainKey();

  let firstFailure = chainFailure;
  let headSigned = false;

  if (key && row.head && head) {
    const signature = headSignature(key, row.head);
    headSigned = signature === 'valid';

    if (!firstFailure && signature === 'invalid') {
      firstFailure = { seq: head.seq, id: null, reason: 'head_mismatch' };
    } else if (!firstFailure && signature !== 'valid') {
      firstFailure = { seq: head.seq, id: null, reason: 'head_unsigned' };
    }
  }

  return {
    verified: firstFailure === null,
    checkedAt: new Date().toISOString(),
    rowsChecked: Number(row.rows_checked),
    firstSeq: toNumber(row.first_seq),
    lastSeq,
    anchorHash: row.anchor_hash,
    head,
    headSigned,
    firstFailure,
  };
}

export class AuditHeadSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditHeadSealError';
  }
}

/**
 * Signs the current chain head with `AUDIT_CHAIN_KEY`, replacing whatever signature it had.
 *
 * This is an operator attesting that the head as it stands is genuine: once after the key
 * is first set, and after the key is rotated. It refuses a chain that does not verify on
 * its own, and holds the head lock throughout so no insert moves the head mid-check.
 */
export async function sealAuditChainHead(): Promise<{ seq: number; hash: string | null }> {
  const key = auditChainKey();
  if (!key) throw new AuditHeadSealError('AUDIT_CHAIN_KEY is not set.');

  return getSequelize().transaction(async (transaction) => {
    await getSequelize().query(
      'SELECT id FROM public.auth_event_chain_head WHERE id = 1 FOR UPDATE',
      { type: QueryTypes.SELECT, transaction },
    );

    const { head, chainFailure } = await inspectChain(transaction);

    if (!head) throw new AuditHeadSealError('The audit chain head row is missing.');
    if (chainFailure) {
      throw new AuditHeadSealError(
        `The audit chain does not verify (${chainFailure.reason} at seq ${chainFailure.seq}). ` +
          'Investigate before signing its head.',
      );
    }

    await getSequelize().query(
      `UPDATE public.auth_event_chain_head
         SET signed_seq = :seq, signature = :signature
         WHERE id = 1`,
      {
        replacements: { seq: head.seq, signature: signAuditHead(key, head.seq, head.hash) },
        transaction,
      },
    );

    return head;
  });
}
