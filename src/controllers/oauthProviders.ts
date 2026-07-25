/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Response } from 'express';

import { getSystemConfig, invalidateSystemConfigCache } from '../config/getSystemConfig.js';
import { resolveSystemConfigUpdatedBy } from '../lib/systemConfigActor.js';
import { SystemConfig } from '../models/systemConfig.js';
import { OAuthProviderConfig, OAuthProviderConfigSchema } from '../schemas/systemConfig.schema.js';
import { AuthEventService } from '../services/authEventService.js';
import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('oauthProviders');

const OAUTH_PROVIDERS_KEY = 'oauth_providers';

type ProviderAudit = {
  action: 'created' | 'updated' | 'deleted';
  providerId: string;
  before: OAuthProviderConfig | null;
  after: OAuthProviderConfig | null;
};

async function persistProviders(
  providers: OAuthProviderConfig[],
  req: ServiceRequest,
  audit: ProviderAudit,
) {
  const updatedBy = resolveSystemConfigUpdatedBy(req);

  await SystemConfig.sequelize!.transaction(async (tx) => {
    await SystemConfig.upsert(
      {
        key: OAUTH_PROVIDERS_KEY,
        value: providers,
        updatedBy,
      },
      { transaction: tx },
    );
  });

  invalidateSystemConfigCache();

  await AuthEventService.log({
    type: 'system_config_updated',
    req,
    metadata: {
      resource: 'oauth_provider',
      action: audit.action,
      providerId: audit.providerId,
      before: audit.before,
      after: audit.after,
    },
  });
}

export async function listOAuthProviders(req: ServiceRequest, res: Response) {
  const config = await getSystemConfig();

  await AuthEventService.log({ type: 'system_config_read', req });

  return res.status(200).json({ providers: config.oauth_providers ?? [] });
}

export async function createOAuthProvider(req: ServiceRequest, res: Response) {
  const provider = req.body as OAuthProviderConfig;

  const config = await getSystemConfig();
  const providers = config.oauth_providers ?? [];

  if (providers.some((existing) => existing.id === provider.id)) {
    return res.status(409).json({ error: `OAuth provider "${provider.id}" already exists` });
  }

  logger.info(`Creating OAuth provider ${provider.id}`);

  await persistProviders([...providers, provider], req, {
    action: 'created',
    providerId: provider.id,
    before: null,
    after: provider,
  });

  return res.status(201).json({ provider });
}

export async function updateOAuthProvider(req: ServiceRequest, res: Response) {
  const { id } = req.params;

  const config = await getSystemConfig();
  const providers = config.oauth_providers ?? [];
  const index = providers.findIndex((existing) => existing.id === id);

  if (index === -1) {
    return res.status(404).json({ error: `OAuth provider "${id}" not found` });
  }

  const merged = OAuthProviderConfigSchema.safeParse({
    ...providers[index],
    ...req.body,
    id,
  });

  if (!merged.success) {
    return res.status(400).json({
      error: 'Invalid OAuth provider payload',
      details: merged.error,
    });
  }

  logger.info(`Updating OAuth provider ${id}`);

  const next = [...providers];
  next[index] = merged.data;

  await persistProviders(next, req, {
    action: 'updated',
    providerId: id,
    before: providers[index],
    after: merged.data,
  });

  return res.status(200).json({ provider: merged.data });
}

export async function deleteOAuthProvider(req: ServiceRequest, res: Response) {
  const { id } = req.params;

  const config = await getSystemConfig();
  const providers = config.oauth_providers ?? [];
  const target = providers.find((existing) => existing.id === id);

  if (!target) {
    return res.status(404).json({ error: `OAuth provider "${id}" not found` });
  }

  logger.info(`Deleting OAuth provider ${id}`);

  await persistProviders(
    providers.filter((existing) => existing.id !== id),
    req,
    { action: 'deleted', providerId: id, before: target, after: null },
  );

  return res.status(200).json({ success: true, id });
}
