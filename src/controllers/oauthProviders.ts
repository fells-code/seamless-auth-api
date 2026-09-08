/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Response } from 'express';

import { invalidateSystemConfigCache } from '../config/getSystemConfig.js';
import { resolveSystemConfigUpdatedBy } from '../lib/systemConfigActor.js';
import { SystemConfig } from '../models/systemConfig.js';
import { OAuthProviderConfig, OAuthProviderConfigSchema } from '../schemas/systemConfig.schema.js';
import { AuthEventService } from '../services/authEventService.js';
import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('oauthProviders');

const OAUTH_PROVIDERS_KEY = 'oauth_providers';

/**
 * The provider id reaches these log lines from the request, which static analysis reads
 * as untrusted, and it is logged anyway. `OAuthProviderIdSchema` holds it to
 * `[a-z0-9-]{2,40}` in `defineRoute` before a handler runs, so it cannot carry a newline
 * or any other control character, and `escapeLogControlCharacters` escapes the class
 * centrally in the logger format regardless. An operator reading logs needs to know
 * which provider changed, and the two guards are what make saying so safe.
 */

type ProviderAudit = {
  action: 'created' | 'updated' | 'deleted';
  providerId: string;
  before: OAuthProviderConfig | null;
  after: OAuthProviderConfig | null;
};

type ProviderRefusal = { status: number; body: Record<string, unknown> };

type ProviderEdit =
  { providers: OAuthProviderConfig[]; audit: ProviderAudit } | { refusal: ProviderRefusal };

/**
 * Applies one edit to the stored provider list, under a lock on the row.
 *
 * The list is a single JSONB value, so changing one provider means reading the array,
 * editing it in memory and writing all of it back. Reading it through `getSystemConfig`
 * outside the transaction made that last-write-wins: two administrators adding a
 * provider at once both read the same array, and the second write dropped the first
 * with no error. Because that cache lives five minutes and is invalidated per process,
 * one instance could also overwrite an addition made through another.
 *
 * The row is read inside the transaction with `FOR UPDATE`, so a concurrent edit waits
 * and then sees the committed list. The caller's checks run on that locked value rather
 * than on a cached copy, which is what makes a duplicate id or a missing provider an
 * answer about the current state instead of a stale one.
 */
async function editProviders(
  req: ServiceRequest,
  edit: (current: OAuthProviderConfig[]) => ProviderEdit,
): Promise<ProviderRefusal | null> {
  const updatedBy = resolveSystemConfigUpdatedBy(req);

  const outcome = await SystemConfig.sequelize!.transaction(async (transaction) => {
    const row = await SystemConfig.findByPk(OAUTH_PROVIDERS_KEY, {
      transaction,
      lock: transaction.LOCK.UPDATE,
    });

    const current = (row?.value as OAuthProviderConfig[] | undefined) ?? [];
    const result = edit(current);

    if ('refusal' in result) {
      return result;
    }

    await SystemConfig.upsert(
      { key: OAUTH_PROVIDERS_KEY, value: result.providers, updatedBy },
      { transaction },
    );

    return result;
  });

  if ('refusal' in outcome) {
    return outcome.refusal;
  }

  invalidateSystemConfigCache();

  await AuthEventService.log({
    type: 'system_config_updated',
    req,
    metadata: {
      resource: 'oauth_provider',
      action: outcome.audit.action,
      providerId: outcome.audit.providerId,
      before: outcome.audit.before,
      after: outcome.audit.after,
    },
  });

  return null;
}

export async function listOAuthProviders(req: ServiceRequest, res: Response) {
  const row = await SystemConfig.findByPk(OAUTH_PROVIDERS_KEY);

  await AuthEventService.log({ type: 'system_config_read', req });

  return res
    .status(200)
    .json({ providers: (row?.value as OAuthProviderConfig[] | undefined) ?? [] });
}

export async function createOAuthProvider(req: ServiceRequest, res: Response) {
  const provider = req.body as OAuthProviderConfig;

  const refusal = await editProviders(req, (providers) => {
    if (providers.some((existing) => existing.id === provider.id)) {
      return {
        refusal: {
          status: 409,
          body: { error: `OAuth provider "${provider.id}" already exists` },
        },
      };
    }

    return {
      providers: [...providers, provider],
      audit: { action: 'created', providerId: provider.id, before: null, after: provider },
    };
  });

  if (refusal) {
    return res.status(refusal.status).json(refusal.body);
  }

  logger.info(`Created OAuth provider ${provider.id}`);

  return res.status(201).json({ provider });
}

export async function updateOAuthProvider(req: ServiceRequest, res: Response) {
  const { id } = req.params;

  let updated: OAuthProviderConfig | null = null;

  const refusal = await editProviders(req, (providers) => {
    const index = providers.findIndex((existing) => existing.id === id);

    if (index === -1) {
      return { refusal: { status: 404, body: { error: `OAuth provider "${id}" not found` } } };
    }

    const merged = OAuthProviderConfigSchema.safeParse({
      ...providers[index],
      ...req.body,
      id,
    });

    if (!merged.success) {
      return {
        refusal: {
          status: 400,
          body: { error: 'Invalid OAuth provider payload', details: merged.error },
        },
      };
    }

    const next = [...providers];
    next[index] = merged.data;
    updated = merged.data;

    return {
      providers: next,
      audit: { action: 'updated', providerId: id, before: providers[index], after: merged.data },
    };
  });

  if (refusal) {
    return res.status(refusal.status).json(refusal.body);
  }

  logger.info(`Updated OAuth provider ${id}`);

  return res.status(200).json({ provider: updated });
}

export async function deleteOAuthProvider(req: ServiceRequest, res: Response) {
  const { id } = req.params;

  const refusal = await editProviders(req, (providers) => {
    const target = providers.find((existing) => existing.id === id);

    if (!target) {
      return { refusal: { status: 404, body: { error: `OAuth provider "${id}" not found` } } };
    }

    return {
      providers: providers.filter((existing) => existing.id !== id),
      audit: { action: 'deleted', providerId: id, before: target, after: null },
    };
  });

  if (refusal) {
    return res.status(refusal.status).json(refusal.body);
  }

  logger.info(`Deleted OAuth provider ${id}`);

  return res.status(200).json({ success: true, id });
}
