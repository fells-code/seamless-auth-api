/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { getSystemConfig } from '../config/getSystemConfig.js';
import { OidcClientLink } from '../models/oidcClientLinks.js';
import type { OidcClient } from '../models/oidcClients.js';
import { findOidcApplication, OidcApplicationError } from './oidcApplicationService.js';
import { findActiveOidcClient } from './oidcClientRegistry.js';

export function serializeOidcClientLink(link: OidcClientLink) {
  return {
    clientId: link.clientId,
    linkedClientId: link.linkedClientId,
    createdBy: link.createdBy ?? null,
    createdAt: new Date(link.createdAt).toISOString(),
  };
}

/**
 * ADR 0002, N4. Checked when a link is made and again on every use, so a client whose
 * party changes after it was linked stops reaching the other's users at once.
 */
async function linkProblem(client: OidcClient, linked: OidcClient): Promise<string | null> {
  if (client.clientType !== 'confidential') {
    return 'Only a confidential application can act for another';
  }
  if (linked.id === client.id) return 'An application cannot be linked to itself';
  if (linked.clientType !== 'public') {
    return 'Only a public application can be acted for; a confidential one sends its own notices';
  }
  if (client.firstParty !== linked.firstParty) {
    return 'Links stay within first-party or within third-party applications';
  }
  if (!client.firstParty && !(await getSystemConfig()).third_party_clients_enabled) {
    return 'Third-party clients are off on this instance (third_party_clients_enabled)';
  }
  return null;
}

export async function listOidcApplicationLinks(id: string) {
  await findOidcApplication(id);

  const [links, linkedFrom] = await Promise.all([
    OidcClientLink.findAll({ where: { clientId: id }, order: [['createdAt', 'ASC']] }),
    OidcClientLink.findAll({ where: { linkedClientId: id }, order: [['createdAt', 'ASC']] }),
  ]);

  return {
    links: links.map(serializeOidcClientLink),
    linkedFrom: linkedFrom.map(serializeOidcClientLink),
  };
}

/** Idempotent: `created` is false when the link already existed. */
export async function addOidcApplicationLink(id: string, linkedId: string, adminId: string | null) {
  const client = await findOidcApplication(id);
  const linked = await findOidcApplication(linkedId);

  const problem = await linkProblem(client, linked);
  if (problem) throw new OidcApplicationError(400, problem);

  const [link, created] = await OidcClientLink.findOrCreate({
    where: { clientId: id, linkedClientId: linkedId },
    defaults: { clientId: id, linkedClientId: linkedId, createdBy: adminId },
  });

  return { link: serializeOidcClientLink(link), created };
}

export async function removeOidcApplicationLink(id: string, linkedId: string) {
  const removed = await OidcClientLink.destroy({
    where: { clientId: id, linkedClientId: linkedId },
  });
  if (!removed) throw new OidcApplicationError(404, 'Link not found');
}

/**
 * The active client `client` may act for, or null when there is no link, the linked
 * client is disabled or gone, or the link no longer meets the rules. Every null answers
 * the caller the same way, so a client cannot probe the registry through it.
 */
export async function findLinkedOidcClient(client: OidcClient, linkedId: string) {
  const link = await OidcClientLink.findOne({
    where: { clientId: client.id, linkedClientId: linkedId },
  });
  if (!link) return null;

  const linked = await findActiveOidcClient(linkedId);
  if (!linked || (await linkProblem(client, linked))) return null;

  return linked;
}
