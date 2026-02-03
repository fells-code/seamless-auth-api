/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
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

import { getSystemConfig } from '../config/getSystemConfig';
import { clearAuthCookies, setAuthCookies } from '../lib/cookie';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../lib/token';
import { AuthEvent } from '../models/authEvents';
import { Session } from '../models/sessions';
import { User } from '../models/users';
import { AuthEventService } from '../services/authEventService';
import { AuthenticatedRequest } from '../types/types';
import getLogger from '../utils/logger';
import { computeSessionTimes, parseDurationToSeconds } from '../utils/utils';
import { Credential } from './../models/credentials';

const logger = getLogger('webauthn');
const AUTH_MODE: 'web' | 'server' = process.env.AUTH_MODE! as 'web' | 'server';

const registerWebAuthn = async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const verifiedUser = authReq.user;
    logger.info(`Registering passwordless mechanism for ${authReq.user?.email}`);

    if (!verifiedUser) {
      logger.error(`Invalid registration user attempt ${JSON.stringify(req)}`);
      await AuthEventService.log({
        userId: null,
        type: 'webauthn_registration_suspicious',
        req,
        metadata: { reason: 'No verified user on the request.' },
      });

      return res.status(403).json({ message: 'Not allowed' });
    }

    if (!verifiedUser.id || !verifiedUser.email) {
      logger.error(`Invalid registration user attempt ${verifiedUser}`);
      await AuthEventService.log({
        userId: null,
        type: 'webauthn_registration_suspicious',
        req,
        metadata: { reason: 'No verified user on the request.' },
      });
      return res.status(403).json({ message: 'Not allowed' });
    }

    const existingCredentials = await Credential.findAll({
      where: { userId: verifiedUser.id },
    });

    const { app_name, rpid } = await getSystemConfig();

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
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
        authenticatorAttachment: 'platform',
      },
    });

    await verifiedUser.update({
      challenge: options.challenge,
    });

    logger.info(`Generated registration options for user ${verifiedUser.email}`);

    await AuthEventService.log({
      userId: verifiedUser.id,
      type: 'webauthn_registration_success',
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
    res.status(500).json({ message: 'Internal Server Error' });
  }
};

const verifyWebAuthnRegistration = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const verifiedUser = authReq.user;

  logger.info(`Verifiying registration of passwordless mechanism for ${authReq.user?.email}`);
  try {
    const { attestationResponse, metadata } = req.body;

    if (!verifiedUser) {
      logger.warn(`Missing verification token ${req.body}`);
      await AuthEvent.create({
        user_id: null,
        type: 'registration_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'No verified user' },
      });
      return res.status(403).json({ message: 'Not allowed' });
    }

    if (!verifiedUser.email || !attestationResponse) {
      await AuthEvent.create({
        user_id: null,
        type: 'registration_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'No verified user' },
      });
      return res.status(403).json({ message: 'Not allowed' });
    }

    const user = await User.findOne({
      where: { email: verifiedUser.email.toLowerCase() },
    });

    if (!user) {
      logger.error(`Verification attempt for unknown user: ${verifiedUser.email}`);
      await AuthEvent.create({
        user_id: null,
        type: 'registration_suspicious',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'Verified user with no user record' },
      });
      return res.status(403).json({ message: 'Not allowed' });
    }

    const expectedChallenge = user.challenge;
    if (!expectedChallenge) {
      await AuthEvent.create({
        user_id: user.id,
        type: 'registration_suspicous',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'Missing challenge for registration' },
      });
      return res.status(403).json({ message: 'Missing challenge' });
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
      await AuthEvent.create({
        user_id: user.id,
        type: 'registration_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'Verification failed' },
      });
      return res.status(500).json({ message: 'An error occured will verifying. Try again' });
    }

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      logger.error(`Failed registration verification for user: ${verifiedUser.email}`);
      await AuthEvent.create({
        user_id: user.id,
        type: 'registration_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'Verification failed' },
      });
      return res.status(403).json({ message: 'Registration failed verification' });
    }

    const { credential, credentialBackedUp, credentialDeviceType } = registrationInfo;

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
      lastUsedAt: new Date(),
    });

    await user.update({
      challenge: null,
      lastLogin: new Date(),
    });

    logger.info(`Passkey credential saved successfully for user: ${verifiedUser.email}`);

    await AuthEvent.create({
      user_id: user.id,
      type: 'credential_created',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'Registration' },
    });

    const refreshToken = generateRefreshToken();
    const refreshTokenHash = await hashRefreshToken(refreshToken);
    const { expiresAt, idleExpiresAt } = computeSessionTimes();

    const session = await Session.create({
      userId: user.id,
      infraId: process.env.APP_ID!,
      mode: AUTH_MODE,
      refreshTokenHash,
      userAgent: req.get('user-agent'),
      ipAddress: req.ip,
      expiresAt,
      idleExpiresAt,
      lastUsedAt: undefined,
    });

    const token = await signAccessToken(session.id, user.id);

    user.challenge = '';
    user.verified = true;

    await user.save();

    if (token && refreshToken) {
      await AuthEvent.create({
        user_id: user.id,
        type: 'registration_success',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: {},
      });

      if (AUTH_MODE === 'web') {
        await setAuthCookies(res, { accessToken: token, refreshToken });
        res.status(200).json({ message: 'Success' });
        return;
      }

      const { access_token_ttl, refresh_token_ttl } = await getSystemConfig();

      return res
        .status(200)
        .json({
          message: 'Success',
          token,
          refreshToken,
          sub: user.id,
          ttl: parseDurationToSeconds(access_token_ttl || '15m'),
          refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1h'),
        });
    }
  } catch (err) {
    logger.error(`Error in verifyWebAuthnRegistration: ${err}`);
    return res.status(500).json({ message: 'Unknown error verifying passkey' });
  }
};

const generateWebAuthn = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const verifiedUser = authReq.user;

  logger.info(`Generating passwordless login for ${verifiedUser.email}`);
  const email = verifiedUser.email;
  const phone = verifiedUser.phone;
  let user = verifiedUser;
  let creds;

  if (!phone && !email) {
    logger.warn('No pre authenticated identifier found');
    await AuthEvent.create({
      user_id: null,
      type: 'login_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'No identifier' },
    });
    return res.status(403).json({ message: 'Not allowed' });
  }

  if (!user) {
    logger.warn('Failed to find a user for generating passkey challenge during auth');
    await AuthEvent.create({
      user_id: null,
      type: 'login_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'No user' },
    });
    return res.status(401).send('Not allowed');
  }

  creds = await Credential.findAll({ where: { userId: user.id } });

  try {
    if (!creds || creds.length === 0) {
      await AuthEvent.create({
        user_id: user.id,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'No credentials' },
      });
      logger.info('Valid user with no credentials');
      return res.status(401).send('Credentials not found');
    }

    const { rpid } = await getSystemConfig();

    const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
      allowCredentials: creds.map((cred) => {
        return {
          id: cred.id,
          transports: cred.transports,
        };
      }),
      userVerification: 'required',
      timeout: 60000,
      rpID: rpid,
    });

    await user.update({
      challenge: options.challenge,
    });

    await AuthEvent.create({
      user_id: null,
      type: 'login_challenge',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: '' },
    });
    return res.json(options);
  } catch (error) {
    if (error instanceof Error) {
      logger.error(`stack ${error.stack}`);
    }
    logger.error(`Failed to generate options for login: ${error}.`);
    await AuthEvent.create({
      user_id: null,
      type: 'login_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'Catch all error' },
    });
    return res.status(500).json({ message: 'Internal server error' });
  }
};

const verifyWebAuthn = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const verifiedUser = authReq.user;

  logger.info(`Verifying passwordless login for ${verifiedUser.email}`);

  try {
    const { assertionResponse } = req.body;
    const email = verifiedUser.email;
    const phone = verifiedUser.phone;
    let user = verifiedUser;

    if (!phone && !email) {
      logger.error('No pre authenticated Identifier found');
      await AuthEvent.create({
        user_id: null,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'No identifier' },
      });
      return res.status(403).json({ message: 'Not allowed' });
    }

    if (!user || !user.challenge) {
      await AuthEvent.create({
        user_id: null,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'No user or user challenge' },
      });
      return res.status(401).json({ message: 'Authentication failed.' });
    }

    const cred = await Credential.findOne({
      where: { userId: user.id, id: assertionResponse.id },
    });

    if (!cred) {
      logger.error(`Failed to find the credental for the user ${assertionResponse.id}`);
      await AuthEvent.create({
        user_id: user.id,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'No credential' },
      });
      return res.status(401).json({ message: 'Authentication failed.' });
    }

    const expectedChallenge = user.challenge;
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

      if (error instanceof Error) {
        logger.error(`Verification failed error stack: ${error.stack}`);
      }
      await AuthEvent.create({
        user_id: user.id,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'Incorrect passkey' },
      });
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (verification.verified) {
      await cred.update({
        lastUsedAt: new Date(),
        counter: verification.authenticationInfo.newCounter,
      });

      const refreshToken = generateRefreshToken();
      const refreshTokenHash = await hashRefreshToken(refreshToken);
      const { expiresAt, idleExpiresAt } = computeSessionTimes();

      const session = await Session.create({
        userId: user.id,
        infraId: process.env.APP_ID!,
        mode: AUTH_MODE,
        refreshTokenHash,
        userAgent: req.get('user-agent'),
        ipAddress: req.ip,
        expiresAt,
        idleExpiresAt,
        lastUsedAt: undefined,
      });

      const token = await signAccessToken(session.id, user.id, user.roles);

      user.challenge = '';
      user.lastLogin = new Date();

      await user.save();

      await AuthEventService.loginSuccess(user.id, req);

      if (token && refreshToken) {
        clearAuthCookies(res);

        if (AUTH_MODE === 'web') {
          await setAuthCookies(res, { accessToken: token, refreshToken: refreshToken });
          res.status(200).json({ message: 'Success' });
          return;
        }

        const { access_token_ttl, refresh_token_ttl } = await getSystemConfig();

        return res.status(200).json({
          message: 'Success',
          token,
          refreshToken,
          sub: user.id,
          roles: user.roles,
          ttl: parseDurationToSeconds(access_token_ttl || '15m'),
          refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1h'),
        });
      }
    } else {
      await AuthEvent.create({
        user_id: null,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'Verification failed' },
      });
      res.status(401).send('Authentication failed');
      return;
    }
  } catch (error) {
    logger.error(`Error occured validating passkey on login: ${error}`);
    await AuthEvent.create({
      user_id: null,
      type: 'login_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'Catch all error' },
    });
    res.status(500).json({ message: 'Internal Server error' });
    return;
  }
};

export { generateWebAuthn, registerWebAuthn, verifyWebAuthn, verifyWebAuthnRegistration };
