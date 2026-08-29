/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  AuthenticatorTransportFuture,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  PublicKeyCredentialRequestOptionsJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import base64url from 'base64url';
import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import {
  buildPrfAuthenticationExtensions,
  buildPrfRegistrationExtensions,
  containsPrfOutput,
  getRegistrationPrfCapable,
} from '../lib/webauthnPrf.js';
import { Credential } from '../models/credentials.js';
import { User } from '../models/users.js';
import type { WebAuthnAuthenticatorAttachment } from '../schemas/webauthn.requests.js';
import { AuthEventService } from '../services/authEventService.js';
import { rejectIfUserLocked } from '../services/lockoutPolicyService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';
import { consumeChallenge, issueChallenge } from '../services/webauthnChallengeService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('webauthn');
function getRegistrationChallengeContext(context: Record<string, unknown> | null | undefined) {
  if (!context) {
    return { prfRequested: false, requirePrf: false };
  }

  return {
    prfRequested: context.prfRequested === true,
    requirePrf: context.requirePrf === true,
  };
}

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

const registerWebAuthn = async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const verifiedUser = authReq.user;
    const {
      requestPrf = false,
      requirePrf = false,
      attachment,
    } = req.query as {
      requestPrf?: boolean;
      requirePrf?: boolean;
      attachment?: WebAuthnAuthenticatorAttachment;
    };
    const prfRequested = requestPrf || requirePrf;
    logger.info('Registering passwordless mechanism');

    if (!verifiedUser) {
      logger.error('Invalid registration user attempt');
      await AuthEventService.log({
        userId: null,
        type: 'webauthn_registration_suspicious',
        req,
        metadata: { reason: 'No verified user on the request.' },
      });

      return res.status(403).json({ error: 'Not allowed' });
    }

    if (!verifiedUser.id || !verifiedUser.email) {
      logger.error('Invalid registration user attempt');
      await AuthEventService.log({
        userId: null,
        type: 'webauthn_registration_suspicious',
        req,
        metadata: { reason: 'No verified user on the request.' },
      });
      return res.status(403).json({ error: 'Not allowed' });
    }

    const existingCredentials = await Credential.findAll({
      where: { userId: verifiedUser.id },
    });

    const { app_name, rpid, authenticator_policy } = await getSystemConfig();
    const pinnedAttachment =
      authenticator_policy.attachment === 'any' ? null : authenticator_policy.attachment;

    // A pinned deployment policy bounds the request, so a caller cannot widen it by
    // asking for the kind the agency has chosen not to enrol.
    if (pinnedAttachment && attachment && attachment !== pinnedAttachment) {
      logger.warn('Registration requested an attachment the deployment policy does not allow');
      await AuthEventService.log({
        userId: verifiedUser.id,
        type: 'webauthn_registration_failed',
        req,
        metadata: {
          reason: 'Requested attachment is not allowed by the authenticator policy',
          requested: attachment,
          allowed: pinnedAttachment,
        },
      });

      return res.status(400).json({ error: 'attachment_not_allowed' });
    }

    const effectiveAttachment = pinnedAttachment ?? attachment;

    const options = await generateRegistrationOptions({
      rpName: app_name,
      rpID: rpid,
      userName: verifiedUser.email,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: existingCredentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports,
      })),
      // Left unset unless the policy pins a kind or the caller asks for one. Pinning
      // this to 'platform' hides roaming authenticators from the browser picker
      // entirely, which makes issued security keys impossible to enrol.
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
        ...(effectiveAttachment ? { authenticatorAttachment: effectiveAttachment } : {}),
      },
      extensions: buildPrfRegistrationExtensions(prfRequested),
    });

    await issueChallenge({
      userId: verifiedUser.id,
      purpose: 'registration',
      challenge: options.challenge,
      context: { prfRequested, requirePrf },
    });

    logger.info('Generated registration options for user');

    // Issuing options is not a registration. The credential does not exist until
    // /register/finish verifies the attestation, which logs registration_success.
    await AuthEventService.log({
      userId: verifiedUser.id,
      type: 'webauthn_registration_challenge',
      req,
    });

    return res.json(options);
  } catch (err: unknown) {
    logger.error(`Error in registerWebAuthn: ${err}`);
    await AuthEventService.log({
      userId: null,
      type: 'webauthn_registration_failed',
      req,
      metadata: { reason: `Server error: ${err}` },
    });
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const verifyWebAuthnRegistration = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const verifiedUser = authReq.user;

  logger.info('Verifying registration of passwordless mechanism');
  try {
    const { attestationResponse, metadata = {} } = req.body;

    if (!verifiedUser) {
      logger.warn('Missing attestation response for WebAuthn registration');
      await AuthEventService.log({
        userId: null,
        type: 'registration_failed',
        req,
        metadata: { reason: 'No verified user' },
      });
      return res.status(403).json({ error: 'Not allowed' });
    }

    if (!verifiedUser.email || !attestationResponse) {
      logger.warn('Missing verified user email or attestation response');
      await AuthEventService.log({
        userId: null,
        type: 'registration_failed',
        req,
        metadata: { reason: 'No verified user' },
      });
      return res.status(403).json({ error: 'Not allowed' });
    }

    const user = await User.findOne({
      where: { email: verifiedUser.email.toLowerCase() },
    });

    if (!user) {
      logger.error('Verification attempt for unknown user');
      await AuthEventService.log({
        userId: null,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Verified user with no user record' },
      });
      return res.status(403).json({ error: 'Not allowed' });
    }

    // Consumed before verification, so the challenge is spent however this
    // attempt turns out and a failure cannot leave one live to replay against.
    const issued = await consumeChallenge({ userId: user.id, purpose: 'registration' });
    const expectedChallenge = issued?.challenge;

    if (!expectedChallenge) {
      logger.error('Unexpected user challegnge supplied.');
      await AuthEventService.log({
        userId: user.id,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Missing challenge for registration' },
      });
      return res.status(403).json({ error: 'Missing challenge' });
    }

    let verification;
    try {
      const { origins, rpid } = await getSystemConfig();

      verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge,
        expectedOrigin: origins,
        expectedRPID: rpid,
      });
    } catch (error) {
      logger.error(`Error perfroming webAuthn verification ${error}`);
      await AuthEventService.log({
        userId: user.id,
        type: 'registration_failed',
        req,
        metadata: { reason: 'Verification failed' },
      });
      return res.status(500).json({ error: 'An error occured will verifying. Try again' });
    }

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      logger.error('Failed registration verification for user');
      await AuthEventService.log({
        userId: user.id,
        type: 'registration_failed',
        req,
        metadata: { reason: 'Verification failed' },
      });
      return res.status(403).json({ error: 'Registration failed verification' });
    }

    const { credential, credentialBackedUp, credentialDeviceType } = registrationInfo;
    const challengeContext = getRegistrationChallengeContext(issued?.context);
    const prfCapable =
      getRegistrationPrfCapable(attestationResponse) || metadata.prfCapable === true;

    if (challengeContext.requirePrf && !prfCapable) {
      await AuthEventService.log({
        userId: user.id,
        type: 'webauthn_registration_failed',
        req,
        metadata: { reason: 'PRF required but credential did not report PRF support' },
      });
      return res.status(403).json({ error: 'prf_required' });
    }

    // @ts-expect-error Ignoring for testing.
    const publicKey = base64url.encode(credential.publicKey);

    await Credential.create({
      id: credential.id,
      userId: user.id,
      publicKey: publicKey,
      counter: credential.counter,
      backedup: credentialBackedUp,
      transports: credential.transports,
      deviceType: credentialDeviceType,
      friendlyName: metadata.friendlyName || null,
      platform: metadata.platform || null,
      browser: metadata.browser || null,
      deviceInfo: metadata.deviceInfo || null,
      prfCapable,
      lastUsedAt: new Date(),
    });

    await user.update({
      lastLogin: new Date(),
      verified: true,
    });

    await AuthEventService.log({
      userId: user.id,
      type: 'registration_success',
      req,
      metadata: {},
    });

    await issueSessionAndRespond({
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        roles: user.roles ?? [],
      },
      req,
      res,
    });

    user.update({
      lastLogin: new Date(),
    });

    return;
  } catch (err) {
    logger.error(`Error in verifyWebAuthnRegistration: ${err}`);
    return res.status(500).json({ error: 'Unknown error verifying passkey' });
  }
};

const generateWebAuthn = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const verifiedUser = authReq.user;
  const { credentialId, prf } = req.body ?? {};

  logger.info('Generating passwordless login');
  const email = verifiedUser.email;
  const phone = verifiedUser.phone;
  let user = verifiedUser;
  let creds;

  if (!phone && !email) {
    logger.warn('No pre authenticated identifier found');
    await AuthEventService.log({
      userId: null,
      type: 'login_failed',
      req,
      metadata: { reason: 'No identifier' },
    });
    return res.status(403).json({ error: 'Not allowed' });
  }

  creds = await Credential.findAll({ where: { userId: user.id } });

  try {
    const assertionCredentials = filterAssertionCredentials(creds ?? [], {
      credentialId,
      requiresPrf: Boolean(prf),
    });

    if (!assertionCredentials || assertionCredentials.length === 0) {
      await AuthEventService.log({
        userId: user.id,
        type: 'login_failed',
        req,
        metadata: { reason: prf ? 'No PRF-capable credentials' : 'No credentials' },
      });
      logger.error('Valid user with no credentials');
      return res.status(401).send('Credentials not found');
    }

    const { rpid } = await getSystemConfig();

    const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
      allowCredentials: assertionCredentials.map((cred) => {
        return {
          id: cred.id,
          transports: cred.transports,
        };
      }),
      userVerification: 'required',
      timeout: 60000,
      rpID: rpid,
      extensions: buildPrfAuthenticationExtensions(prf),
    });

    await issueChallenge({
      userId: user.id,
      purpose: 'authentication',
      challenge: options.challenge,
    });

    await AuthEventService.log({
      userId: null,
      type: 'login_challenge',
      req,
      metadata: { reason: '' },
    });
    return res.json(options);
  } catch (error) {
    if (error instanceof Error) {
      logger.error('Failed to generate options for login stack trace redacted');
    }
    await AuthEventService.log({
      userId: null,
      type: 'login_failed',
      req,
      metadata: { reason: 'Catch all error' },
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
};

const verifyWebAuthn = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const verifiedUser = authReq.user;

  logger.info('Verifying passwordless login');

  try {
    const { assertionResponse } = req.body;

    if (containsPrfOutput(assertionResponse)) {
      await AuthEventService.log({
        userId: verifiedUser.id,
        type: 'webauthn_login_failed',
        req,
        metadata: { reason: 'PRF output was sent to the server' },
      });
      return res.status(400).json({ error: 'prf_output_not_allowed' });
    }

    const email = verifiedUser.email;
    const phone = verifiedUser.phone;
    let user = verifiedUser;

    if (await rejectIfUserLocked({ userId: user.id, req, res })) {
      return;
    }

    if (!phone && !email) {
      logger.error('No pre authenticated Identifier found');
      await AuthEventService.log({
        userId: null,
        type: 'login_failed',
        req,
        metadata: { reason: 'No identifier' },
      });
      return res.status(403).json({ error: 'Not allowed' });
    }

    // Consumed before anything else can fail, so this path cannot leave a live
    // challenge behind for an assertion to be replayed against.
    const issued = user
      ? await consumeChallenge({ userId: user.id, purpose: 'authentication' })
      : null;

    if (!user || !issued) {
      logger.error('User or user challenge missing');
      await AuthEventService.log({
        userId: user.id,
        type: 'webauthn_login_failed',
        req,
        metadata: { reason: 'No user or user challenge' },
      });

      return res.status(401).json({ error: 'Authentication failed.' });
    }

    const cred = await Credential.findOne({
      where: { userId: user.id, id: assertionResponse.id },
    });

    if (!cred) {
      logger.error('Failed to find the credential for the user');

      await AuthEventService.log({
        userId: user.id,
        type: 'webauthn_login_failed',
        req,
        metadata: { reason: 'No credential' },
      });

      return res.status(401).json({ error: 'Authentication failed.' });
    }

    const expectedChallenge = issued.challenge;
    let verification;

    try {
      const { origins, rpid } = await getSystemConfig();
      verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge,
        expectedOrigin: origins,
        expectedRPID: rpid,
        credential: {
          id: cred.id,
          // @ts-expect-error Needed to work.
          publicKey: base64url.toBuffer(cred.publicKey),
          counter: cred.counter,
          transports: cred.transports as AuthenticatorTransportFuture[],
        },
      });
    } catch (error) {
      logger.error(`Verification failed in webAuthn for login: ${error}`);
      await AuthEventService.log({
        userId: user.id,
        type: 'webauthn_login_failed',
        req,
        metadata: { reason: 'Incorrect passkey' },
      });

      return res.status(500).json({ error: 'Internal server error' });
    }

    if (verification.verified) {
      await cred.update({
        lastUsedAt: new Date(),
        counter: verification.authenticationInfo.newCounter,
      });

      await AuthEventService.log({
        userId: user.id,
        type: 'webauthn_login_success',
        req,
        metadata: { reason: 'Successful login' },
      });

      await issueSessionAndRespond({
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          roles: user.roles ?? [],
        },
        req,
        res,
      });

      user.update({
        lastLogin: new Date(),
      });

      return;
    }
  } catch (error) {
    logger.error(`Error occured validating passkey on login: ${error}`);
    await AuthEventService.log({
      userId: null,
      type: 'login_failed',
      req,
      metadata: { reason: 'Catch all error' },
    });
    res.status(500).json({ error: 'Internal Server error' });
    return;
  }
};

export { generateWebAuthn, registerWebAuthn, verifyWebAuthn, verifyWebAuthnRegistration };
