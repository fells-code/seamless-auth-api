/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  createOAuthProvider,
  deleteOAuthProvider,
  listOAuthProviders,
  refreshOAuthProviderDiscovery,
  updateOAuthProvider,
} from '../controllers/oauthProviders.js';
import {
  discardPolicyDraftHandler,
  dryRunPolicyHandler,
  getPolicyStateHandler,
  listPolicyVersionsHandler,
  publishPolicyHandler,
  rollbackPolicyHandler,
  savePolicyDraftHandler,
} from '../controllers/policy.js';
import {
  getAvailableRoles,
  getPublicSystemConfig,
  getSystemConfigHandler,
  updateSystemConfig,
} from '../controllers/systemConfig.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import {
  ErrorSchema,
  InternalErrorSchema,
  SecretRequiredSchema,
} from '../schemas/generic.responses.js';
import {
  OAuthProviderCreateSchema,
  OAuthProviderIdParamSchema,
  OAuthProviderUpdateSchema,
} from '../schemas/oauthProviders.requests.js';
import {
  OAuthProviderDeletedResponseSchema,
  OAuthProviderResponseSchema,
  OAuthProvidersListResponseSchema,
} from '../schemas/oauthProviders.responses.js';
import {
  MessageResponseSchema,
  PolicyDraftSaveRequestSchema,
  PolicyDraftSchema,
  PolicyDryRunRequestSchema,
  PolicyDryRunResponseSchema,
  PolicyPublishRequestSchema,
  PolicyRollbackRequestSchema,
  PolicyStateResponseSchema,
  PolicyVersionSchema,
  PolicyVersionsResponseSchema,
} from '../schemas/policy.schema.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';
import { SystemConfigPatchSchema } from '../schemas/systemConfig.patch.schema.js';
import {
  AvailableRolesResponseSchema,
  GetSystemConfigResponseSchema,
  InvalidPayloadSchema,
  PublicSystemConfigResponseSchema,
  UpdateSystemConfigResponseSchema,
} from '../schemas/systemConfig.responses.js';

const systemConfigRouter = createRouter('/system-config');

// Unauthenticated on purpose. The bundled sign-in screens render before anyone
// has a session, and this is what lets them offer the methods an instance
// actually has enabled instead of a hardcoded guess. It exposes only the login
// method list, which the sign-in screens already reveal by their behaviour.
systemConfigRouter.get(
  '/public',
  {
    adapter: {},
    summary: 'Read the publicly visible system configuration',
    tags: ['SystemConfig'],

    schemas: {
      response: {
        200: PublicSystemConfigResponseSchema,
      },
    },
  },
  getPublicSystemConfig,
);

systemConfigRouter.get(
  '/roles',
  {
    auth: 'access',
    summary: 'Get available roles',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],
    schemas: {
      response: {
        200: AvailableRolesResponseSchema,
      },
    },
  },
  getAvailableRoles,
);

systemConfigRouter.get(
  '/admin',
  {
    auth: 'access',
    summary: 'Retrieve system configuration',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],

    schemas: {
      response: {
        200: GetSystemConfigResponseSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  getSystemConfigHandler,
);

systemConfigRouter.patch(
  '/admin',
  {
    auth: 'access',
    summary: 'Update system configuration',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      body: SystemConfigPatchSchema,
      response: {
        200: UpdateSystemConfigResponseSchema,
        400: InvalidPayloadSchema,
        401: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        409: SecretRequiredSchema,
      },
    },
  },
  updateSystemConfig,
);

systemConfigRouter.get(
  '/oauth-providers',
  {
    auth: 'access',
    summary: 'List configured OAuth providers',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],

    schemas: {
      response: {
        200: OAuthProvidersListResponseSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  listOAuthProviders,
);

systemConfigRouter.post(
  '/oauth-providers',
  {
    auth: 'access',
    summary: 'Add an OAuth provider',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      body: OAuthProviderCreateSchema,
      response: {
        201: OAuthProviderResponseSchema,
        400: InvalidPayloadSchema,
        401: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        409: SecretRequiredSchema,
      },
    },
  },
  createOAuthProvider,
);

systemConfigRouter.post(
  '/oauth-providers/:id/discovery',
  {
    auth: 'access',
    summary: "Refresh an OAuth provider's endpoints and keys from its issuer",
    description:
      "A provider with an `issuer` reads any endpoint it does not configure from the issuer's `/.well-known/openid-configuration`, cached for an hour. This reads the document again now, checks the issuer it names, and drops the cached signing keys so the next sign-in fetches them. Nothing is stored; the answer is the provider as sign-in will use it. Answers 502 when the document cannot be read or is refused.",
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      params: OAuthProviderIdParamSchema,
      response: {
        200: OAuthProviderResponseSchema,
        400: InvalidPayloadSchema,
        401: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
        502: ErrorSchema,
      },
    },
  },
  refreshOAuthProviderDiscovery,
);

systemConfigRouter.patch(
  '/oauth-providers/:id',
  {
    auth: 'access',
    summary: 'Update an OAuth provider',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      params: OAuthProviderIdParamSchema,
      body: OAuthProviderUpdateSchema,
      response: {
        200: OAuthProviderResponseSchema,
        400: InvalidPayloadSchema,
        401: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  updateOAuthProvider,
);

systemConfigRouter.delete(
  '/oauth-providers/:id',
  {
    auth: 'access',
    summary: 'Remove an OAuth provider',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      params: OAuthProviderIdParamSchema,
      response: {
        200: OAuthProviderDeletedResponseSchema,
        401: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  deleteOAuthProvider,
);

systemConfigRouter.get(
  '/policy',
  {
    auth: 'access',
    summary: 'Read the published auth policy and the draft, if any',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],

    schemas: {
      response: {
        200: PolicyStateResponseSchema,
        401: ErrorSchema,
      },
    },
  },
  getPolicyStateHandler,
);

systemConfigRouter.put(
  '/policy/draft',
  {
    auth: 'access',
    summary: 'Save the auth policy draft',
    description:
      'Replaces the single draft. A draft changes nothing until it is published, and keeps ' +
      'the version it was started from across saves.',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write')],

    schemas: {
      body: PolicyDraftSaveRequestSchema,
      response: {
        200: PolicyDraftSchema,
        401: ErrorSchema,
      },
    },
  },
  savePolicyDraftHandler,
);

systemConfigRouter.delete(
  '/policy/draft',
  {
    auth: 'access',
    summary: 'Discard the auth policy draft',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write')],

    schemas: {
      response: {
        200: MessageResponseSchema,
        401: ErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  discardPolicyDraftHandler,
);

systemConfigRouter.post(
  '/policy/publish',
  {
    auth: 'access',
    summary: 'Publish the auth policy draft',
    description:
      'Applies the draft to system config and records it as the next version in one ' +
      'transaction. Answers 409 when expectedVersion is no longer the published version.',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      body: PolicyPublishRequestSchema,
      response: {
        200: PolicyVersionSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        404: ErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  publishPolicyHandler,
);

systemConfigRouter.post(
  '/policy/rollback',
  {
    auth: 'access',
    summary: 'Roll the auth policy back to an earlier version',
    description:
      'Publishes a copy of the named version as the next version. Answers 409 when ' +
      'expectedVersion is no longer the published version.',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      body: PolicyRollbackRequestSchema,
      response: {
        200: PolicyVersionSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        404: ErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  rollbackPolicyHandler,
);

systemConfigRouter.get(
  '/policy/versions',
  {
    auth: 'access',
    summary: 'List published auth policy versions, newest first',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],

    schemas: {
      response: {
        200: PolicyVersionsResponseSchema,
        401: ErrorSchema,
      },
    },
  },
  listPolicyVersionsHandler,
);

systemConfigRouter.post(
  '/policy/dry-run',
  {
    auth: 'access',
    summary: 'Evaluate an auth policy against recent sign-ins',
    description:
      'Evaluates the policy in the request, or the draft when none is sent, against the ' +
      'sign-ins of the last `days` days. Evaluates at most 10,000 accounts.',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],

    schemas: {
      body: PolicyDryRunRequestSchema,
      response: {
        200: PolicyDryRunResponseSchema,
        400: ErrorSchema,
        401: ErrorSchema,
      },
    },
  },
  dryRunPolicyHandler,
);

export default systemConfigRouter.router;
