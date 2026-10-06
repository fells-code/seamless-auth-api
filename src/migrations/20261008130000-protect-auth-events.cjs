/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Makes `auth_events` append-only and tamper-evident (NIST 800-53 AU-9).
 *
 * - Every row is hashed into a chain: `hash = sha256(prev_hash || auth_event_payload(row))`,
 *   with `seq` giving the order. Editing, removing or reordering a row breaks the chain
 *   from that point on, which `GET /admin/auth-events/integrity` reports.
 * - The chain head lives in a one-row table and is advanced with an UPDATE, so concurrent
 *   inserts queue on its row lock and each one reads the head the previous one committed.
 *   Reading the newest row instead would let two inserts link to the same predecessor.
 * - UPDATE and TRUNCATE are refused outright. DELETE is refused unless the transaction
 *   has set `seamless.audit_retention = 'on'`, which only the retention job does.
 * - The user foreign key is dropped. Its ON DELETE SET NULL rewrote audit rows whenever a
 *   user was deleted, which an append-only table cannot allow and which would have broken
 *   the chain. Rows now keep the id of the user they were about.
 *
 * The triggers stop the application from altering the trail in normal operation. They do
 * not stop a role that owns the table, which can disable them. Running the application
 * as a role without UPDATE, DELETE and TRUNCATE on the table, and recording the chain
 * head somewhere outside the database, is what covers that. See docs/security-posture.md.
 *
 * When a column is added to auth_events, add it to auth_event_payload as well, or its
 * value is not covered by the chain.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      const run = (sql) => queryInterface.sequelize.query(sql, { transaction });

      await run(`
        ALTER TABLE public.auth_events DROP CONSTRAINT IF EXISTS auth_events_user_id_fkey;

        ALTER TABLE public.auth_events
          ADD COLUMN seq bigint,
          ADD COLUMN prev_hash character(64),
          ADD COLUMN hash character(64);

        CREATE TABLE public.auth_event_chain_head (
          id smallint PRIMARY KEY CHECK (id = 1),
          seq bigint NOT NULL,
          last_hash character(64)
        );
      `);

      await run(`
        CREATE FUNCTION public.auth_event_payload(e public.auth_events)
        RETURNS text
        LANGUAGE sql
        STABLE
        AS $$
          SELECT jsonb_build_array(
            e.seq,
            e.id,
            e.user_id,
            e.actor_user_id,
            e.session_id,
            e.type,
            e.ip_address,
            e.user_agent,
            e.deployment_id,
            e.device_class,
            e.mail_provider,
            e.owner,
            e.attempt_id,
            e.metadata,
            to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
          )::text
        $$;

        CREATE FUNCTION public.auth_event_hash(prev_hash text, payload text)
        RETURNS character(64)
        LANGUAGE sql
        IMMUTABLE
        AS $$
          SELECT encode(sha256(convert_to(coalesce(prev_hash, '') || payload, 'UTF8')), 'hex')
        $$;
      `);

      // Existing rows are chained in the order they were written. Done before the
      // triggers exist, since the append-only one would refuse these updates.
      await run(`
        DO $$
        DECLARE
          r record;
          n bigint := 0;
          prev character(64) := NULL;
          next_hash character(64);
        BEGIN
          FOR r IN SELECT id FROM public.auth_events ORDER BY created_at, id LOOP
            n := n + 1;
            UPDATE public.auth_events SET seq = n, prev_hash = prev WHERE id = r.id;
            SELECT public.auth_event_hash(prev, public.auth_event_payload(e.*))
              INTO next_hash
              FROM public.auth_events e
              WHERE e.id = r.id;
            UPDATE public.auth_events SET hash = next_hash WHERE id = r.id;
            prev := next_hash;
          END LOOP;

          INSERT INTO public.auth_event_chain_head (id, seq, last_hash) VALUES (1, n, prev);
        END $$;
      `);

      await run(`
        ALTER TABLE public.auth_events
          ALTER COLUMN seq SET NOT NULL,
          ALTER COLUMN hash SET NOT NULL;

        CREATE UNIQUE INDEX auth_events_seq_key ON public.auth_events USING btree (seq);

        CREATE FUNCTION public.auth_events_chain()
        RETURNS trigger
        LANGUAGE plpgsql
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

        CREATE FUNCTION public.auth_events_append_only()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF TG_OP = 'DELETE' AND current_setting('seamless.audit_retention', true) = 'on' THEN
            RETURN OLD;
          END IF;

          RAISE EXCEPTION 'auth_events is append-only: % refused', TG_OP
            USING ERRCODE = 'insufficient_privilege';
        END
        $$;

        CREATE TRIGGER auth_events_chain
          BEFORE INSERT ON public.auth_events
          FOR EACH ROW EXECUTE FUNCTION public.auth_events_chain();

        CREATE TRIGGER auth_events_append_only
          BEFORE UPDATE OR DELETE ON public.auth_events
          FOR EACH ROW EXECUTE FUNCTION public.auth_events_append_only();

        CREATE TRIGGER auth_events_no_truncate
          BEFORE TRUNCATE ON public.auth_events
          FOR EACH STATEMENT EXECUTE FUNCTION public.auth_events_append_only();
      `);
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.sequelize.query(
        `
        DROP TRIGGER IF EXISTS auth_events_no_truncate ON public.auth_events;
        DROP TRIGGER IF EXISTS auth_events_append_only ON public.auth_events;
        DROP TRIGGER IF EXISTS auth_events_chain ON public.auth_events;
        DROP FUNCTION IF EXISTS public.auth_events_append_only();
        DROP FUNCTION IF EXISTS public.auth_events_chain();
        DROP INDEX IF EXISTS public.auth_events_seq_key;

        ALTER TABLE public.auth_events
          DROP COLUMN IF EXISTS hash,
          DROP COLUMN IF EXISTS prev_hash;

        DROP FUNCTION IF EXISTS public.auth_event_hash(text, text);
        DROP FUNCTION IF EXISTS public.auth_event_payload(public.auth_events);

        ALTER TABLE public.auth_events DROP COLUMN IF EXISTS seq;
        DROP TABLE IF EXISTS public.auth_event_chain_head;

        UPDATE public.auth_events e
          SET user_id = NULL
          WHERE user_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = e.user_id);

        ALTER TABLE ONLY public.auth_events
          ADD CONSTRAINT auth_events_user_id_fkey FOREIGN KEY (user_id)
          REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;
        `,
        { transaction },
      );
    });
  },
};
