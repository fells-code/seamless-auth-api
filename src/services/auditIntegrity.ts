/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes } from 'sequelize';

import { getSequelize } from '../models/index.js';

export type ChainFailureReason = 'hash_mismatch' | 'broken_link' | 'sequence_gap' | 'head_mismatch';

export interface AuditIntegrityReport {
  verified: boolean;
  checkedAt: string;
  rowsChecked: number;
  firstSeq: number | null;
  lastSeq: number | null;
  /** The `prev_hash` of the oldest remaining row: the last hash retention archived away. */
  anchorHash: string | null;
  head: { seq: number; hash: string | null } | null;
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
    reason: Exclude<ChainFailureReason, 'head_mismatch'>;
  } | null;
  head: { seq: string; hash: string | null } | null;
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
        SELECT seq, last_hash AS hash FROM public.auth_event_chain_head WHERE id = 1
      ) h
    ) AS head
`;

const toNumber = (value: string | null) => (value === null ? null : Number(value));

/**
 * Walks the whole audit chain and reports the first place it does not hold.
 *
 * A row whose content changed fails its own hash. A row removed from the middle leaves a
 * gap in `seq`. Rows removed from the end leave the chain head ahead of the newest row.
 * Rewriting the entire chain consistently is not detectable from inside the database,
 * which is why the head this returns is worth recording somewhere else.
 */
export async function verifyAuthEventChain(): Promise<AuditIntegrityReport> {
  const [row] = await getSequelize().query<ChainRow>(VERIFY_CHAIN_SQL, {
    type: QueryTypes.SELECT,
  });

  const head = row.head ? { seq: Number(row.head.seq), hash: row.head.hash } : null;
  const lastSeq = toNumber(row.last_seq);

  let firstFailure: AuditIntegrityReport['firstFailure'] = row.first_failure
    ? {
        seq: Number(row.first_failure.seq),
        id: row.first_failure.id,
        reason: row.first_failure.reason,
      }
    : null;

  const headMatches =
    head !== null && head.seq === (lastSeq ?? head.seq) && head.hash === row.last_hash;

  if (!firstFailure && !headMatches) {
    firstFailure = { seq: head?.seq ?? lastSeq ?? 0, id: null, reason: 'head_mismatch' };
  }

  return {
    verified: firstFailure === null,
    checkedAt: new Date().toISOString(),
    rowsChecked: Number(row.rows_checked),
    firstSeq: toNumber(row.first_seq),
    lastSeq,
    anchorHash: row.anchor_hash,
    head,
    firstFailure,
  };
}
