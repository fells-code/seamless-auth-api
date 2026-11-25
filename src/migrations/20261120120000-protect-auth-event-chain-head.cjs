/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

const { createHmac } = require('crypto');

/**
 * Protects `auth_event_chain_head` the way `auth_events` is protected, and gives it a
 * signature a server secret makes.
 *
 * Before this the head was an ordinary table. A role that could delete from the end of
 * `auth_events` could move the head back to match, and the chain verified. Now:
 *
 * - A trigger refuses INSERT, DELETE and TRUNCATE on the head, and refuses any change to
 *   `seq` or `last_hash` that does not come from the `auth_events` insert trigger. That
 *   trigger now runs as SECURITY DEFINER, so the application role needs no write access
 *   to the head columns at all.
 * - `signed_seq` and `signature` carry an HMAC of the head under `AUDIT_CHAIN_KEY`, which
 *   the database never sees. The application moves it forward on every insert. A head
 *   moved back over a truncated tail has no valid signature, and making one takes the key.
 *   The trigger refuses clearing the signature or moving `signed_seq` backwards.
 *
 * When `AUDIT_CHAIN_KEY` is set while this runs, the current head is signed here.
 * Otherwise it stays unsigned until an operator signs it with the seal script. The
 * signing format must match `signAuditHead` in src/services/auditHeadSignature.ts.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      const run = (sql, replacements) =>
        queryInterface.sequelize.query(sql, { transaction, replacements });

      await run(`
        ALTER TABLE public.auth_event_chain_head
          ADD COLUMN signed_seq bigint,
          ADD COLUMN signature character(64);
      `);

      const key = process.env.AUDIT_CHAIN_KEY && process.env.AUDIT_CHAIN_KEY.trim();
      if (key) {
        const [[head]] = await run(
          'SELECT seq, last_hash FROM public.auth_event_chain_head WHERE id = 1 FOR UPDATE',
        );

        if (head) {
          const signature = createHmac('sha256', key)
            .update(`seamless-audit-head:v1:${head.seq}:${head.last_hash ?? ''}`)
            .digest('hex');

          await run(
            'UPDATE public.auth_event_chain_head SET signed_seq = seq, signature = :signature WHERE id = 1',
            { signature },
          );
        }
      }

      await run(`
        -- Redefined, not only altered: as SECURITY DEFINER every call it makes must match
        -- its target exactly, or a better-matching overload created in public by another
        -- role would run with the owner's privileges. prev_hash is character(64), hence
        -- the cast to the text parameter auth_event_hash declares.
        CREATE OR REPLACE FUNCTION public.auth_events_chain()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
          head record;
        BEGIN
          UPDATE public.auth_event_chain_head
            SET seq = seq + 1
            WHERE id = 1
            RETURNING seq, last_hash INTO head;

          NEW.seq := head.seq;
          NEW.prev_hash := head.last_hash;
          NEW.hash := public.auth_event_hash(NEW.prev_hash::text, public.auth_event_payload(NEW));

          UPDATE public.auth_event_chain_head SET last_hash = NEW.hash WHERE id = 1;

          RETURN NEW;
        END
        $$;

        REVOKE ALL ON FUNCTION public.auth_events_chain() FROM PUBLIC;

        CREATE FUNCTION public.auth_event_chain_head_guard()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF TG_OP <> 'UPDATE' THEN
            RAISE EXCEPTION 'auth_event_chain_head: % refused', TG_OP
              USING ERRCODE = 'insufficient_privilege';
          END IF;

          IF NEW.id IS DISTINCT FROM OLD.id THEN
            RAISE EXCEPTION 'auth_event_chain_head: id is fixed'
              USING ERRCODE = 'insufficient_privilege';
          END IF;

          -- Depth 1 is a statement aimed at this table. The auth_events insert trigger
          -- updating it is depth 2.
          IF (NEW.seq, NEW.last_hash) IS DISTINCT FROM (OLD.seq, OLD.last_hash)
            AND (pg_trigger_depth() < 2 OR NEW.seq < OLD.seq) THEN
            RAISE EXCEPTION 'auth_event_chain_head: the head only moves when an event is inserted'
              USING ERRCODE = 'insufficient_privilege';
          END IF;

          IF (NEW.signed_seq, NEW.signature) IS DISTINCT FROM (OLD.signed_seq, OLD.signature)
            AND (
              NEW.signed_seq IS NULL
              OR NEW.signature IS NULL
              OR NEW.signed_seq > NEW.seq
              OR NEW.signed_seq < OLD.signed_seq
            ) THEN
            RAISE EXCEPTION 'auth_event_chain_head: the signature can only move forward'
              USING ERRCODE = 'insufficient_privilege';
          END IF;

          RETURN NEW;
        END
        $$;

        CREATE TRIGGER auth_event_chain_head_guard
          BEFORE INSERT OR UPDATE OR DELETE ON public.auth_event_chain_head
          FOR EACH ROW EXECUTE FUNCTION public.auth_event_chain_head_guard();

        CREATE TRIGGER auth_event_chain_head_no_truncate
          BEFORE TRUNCATE ON public.auth_event_chain_head
          FOR EACH STATEMENT EXECUTE FUNCTION public.auth_event_chain_head_guard();
      `);
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.sequelize.query(
        `
        DROP TRIGGER IF EXISTS auth_event_chain_head_no_truncate ON public.auth_event_chain_head;
        DROP TRIGGER IF EXISTS auth_event_chain_head_guard ON public.auth_event_chain_head;
        DROP FUNCTION IF EXISTS public.auth_event_chain_head_guard();

        CREATE OR REPLACE FUNCTION public.auth_events_chain()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY INVOKER
        AS $$
        DECLARE
          head record;
        BEGIN
          UPDATE public.auth_event_chain_head
            SET seq = seq + 1
            WHERE id = 1
            RETURNING seq, last_hash INTO head;

          NEW.seq := head.seq;
          NEW.prev_hash := head.last_hash;
          NEW.hash := public.auth_event_hash(NEW.prev_hash, public.auth_event_payload(NEW));

          UPDATE public.auth_event_chain_head SET last_hash = NEW.hash WHERE id = 1;

          RETURN NEW;
        END
        $$;

        ALTER TABLE public.auth_event_chain_head
          DROP COLUMN IF EXISTS signature,
          DROP COLUMN IF EXISTS signed_seq;
        `,
        { transaction },
      );
    });
  },
};
