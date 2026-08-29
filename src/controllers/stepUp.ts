/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  AuthenticatorTransportFuture,
  generateAuthenticationOptions,
  PublicKeyCredentialRequestOptionsJSON,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import base64url from 'base64url';
import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { buildPrfAuthenticationExtensions, containsPrfOutput } from '../lib/webauthnPrf.js';
import { Credential } from '../models/credentials.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  getSessionStepUpStatus,
  recordStepUpVerification,
  serializeStepUpStatus,
} from '../services/stepUpService.js';
import { consumeChallenge, issueChallenge } from '../services/webauthnChallengeService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('step-up');

function filterAssertionCredentials(
  credentials: Credential[],
  options: { credentialId?: string; requiresPrf: boolean },
) {
  return credentials.filter((credential) => {
    if (options.credentialId && credential.id !== options.credentialId) {
      return false;
    }

    if (options.requiresPrf && !credential.prfCapable) {
      return false;
    }

    return true;
  });
}

export const getStepUpStatus = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;

  if (!user?.id || !authReq.sessionId) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const status = await getSessionStepUpStatus({
    sessionId: authReq.sessionId,
    userId: user.id,
  });

  if (!status.sessionFound) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  return res.json(serializeStepUpStatus(status));
};

export const startWebAuthnStepUp = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const { credentialId, prf } = req.body ?? {};

  if (!user?.id) {
    await AuthEventService.log({
      userId: null,
      type: 'step_up_suspicious',
      req,
      metadata: { reason: 'No authenticated user' },
    });
    return res.status(401).json({ error: 'unauthorized' });
  }

  try {
    const credentials = await Credential.findAll({ where: { userId: user.id } });

    const assertionCredentials = filterAssertionCredentials(credentials ?? [], {
      credentialId,
      requiresPrf: Boolean(prf),
    });

    if (!assertionCredentials || assertionCredentials.length === 0) {
      await AuthEventService.log({
        userId: user.id,
        type: 'step_up_failed',
        req,
        metadata: {
          reason: prf ? 'No PRF-capable WebAuthn credentials' : 'No WebAuthn credentials',
        },
      });
      return res.status(401).json({ error: 'step_up_unavailable' });
    }

    const { rpid } = await getSystemConfig();
    const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
      allowCredentials: assertionCredentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
      userVerification: 'required',
      timeout: 60000,
      rpID: rpid,
      extensions: buildPrfAuthenticationExtensions(prf),
    });

    await issueChallenge({
      userId: user.id,
      purpose: 'step_up',
      challenge: options.challenge,
    });

    await AuthEventService.log({
      userId: user.id,
      type: 'step_up_challenge',
      req,
      metadata: { method: 'webauthn' },
    });

    return res.json(options);
  } catch (error) {
    logger.error(`Failed to start WebAuthn step-up: ${error}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'step_up_failed',
      req,
      metadata: { reason: 'Failed to generate WebAuthn options' },
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const finishWebAuthnStepUp = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;

  if (!user?.id || !authReq.sessionId) {
    await AuthEventService.log({
      userId: null,
      type: 'step_up_suspicious',
      req,
      metadata: { reason: 'No authenticated user or session' },
    });
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { assertionResponse } = req.body;
  const assertionId = assertionResponse?.id;

  if (containsPrfOutput(assertionResponse)) {
    await AuthEventService.log({
      userId: user.id,
      type: 'step_up_failed',
      req,
      metadata: { reason: 'PRF output was sent to the server' },
    });
    return res.status(400).json({ error: 'prf_output_not_allowed' });
  }

  // Consumed before the credential lookup, so every exit below leaves the
  // challenge spent rather than live.
  const issued = await consumeChallenge({ userId: user.id, purpose: 'step_up' });

  if (!issued || typeof assertionId !== 'string') {
    await AuthEventService.log({
      userId: user.id,
      type: 'step_up_failed',
      req,
      metadata: { reason: 'Missing challenge or assertion id' },
    });
    return res.status(401).json({ error: 'step_up_failed' });
  }

  const credential = await Credential.findOne({
    where: { userId: user.id, id: assertionId },
  });

  if (!credential) {
    await AuthEventService.log({
      userId: user.id,
      type: 'step_up_failed',
      req,
      metadata: { reason: 'Credential not found' },
    });
    return res.status(401).json({ error: 'step_up_failed' });
  }

  const expectedChallenge = issued.challenge;

  try {
    const { origins, rpid } = await getSystemConfig();
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin: origins,
      expectedRPID: rpid,
      credential: {
        id: credential.id,
        // @ts-expect-error SimpleWebAuthn expects a Uint8Array-compatible public key here.
        publicKey: base64url.toBuffer(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports as AuthenticatorTransportFuture[],
      },
    });

    if (!verification.verified) {
      await AuthEventService.log({
        userId: user.id,
        type: 'step_up_failed',
        req,
        metadata: { reason: 'Verification failed' },
      });
      return res.status(401).json({ error: 'step_up_failed' });
    }

    await credential.update({
      lastUsedAt: new Date(),
      counter: verification.authenticationInfo.newCounter,
    });

    const status = await recordStepUpVerification({
      sessionId: authReq.sessionId,
      userId: user.id,
      method: 'webauthn',
    });

    if (!status) {
      await AuthEventService.log({
        userId: user.id,
        type: 'step_up_failed',
        req,
        metadata: { reason: 'Session not found' },
      });
      return res.status(401).json({ error: 'unauthorized' });
    }

    await AuthEventService.log({
      userId: user.id,
      type: 'step_up_success',
      req,
      metadata: { method: 'webauthn' },
    });

    return res.json({
      message: 'Success',
      ...serializeStepUpStatus(status),
      method: 'webauthn',
    });
  } catch (error) {
    logger.error(`Failed to finish WebAuthn step-up: ${error}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'step_up_failed',
      req,
      metadata: { reason: 'Verification error' },
    });
    return res.status(401).json({ error: 'step_up_failed' });
  }
};
