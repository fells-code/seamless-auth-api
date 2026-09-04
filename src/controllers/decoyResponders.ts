/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { generateAuthenticationOptions, generateRegistrationOptions } from '@simplewebauthn/server';
import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { canReturnExternalDelivery } from '../lib/externalDelivery.js';
import { signEphemeralToken } from '../lib/token.js';
import { SUPPORTED_ALGORITHM_IDS } from '../lib/webauthnAlgorithms.js';
import {
  buildPrfAuthenticationExtensions,
  buildPrfRegistrationExtensions,
} from '../lib/webauthnPrf.js';
import type { WebAuthnAuthenticatorAttachment } from '../schemas/webauthn.requests.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  decoyCredentialIdFor,
  decoyOtpFor,
  decoyPrincipalForSubject,
} from '../services/decoyPrincipal.js';
import {
  getLoginPolicy,
  isLoginMethodEnabled,
  LoginMethod,
} from '../services/loginPolicyService.js';
import {
  MagicLinkRedirectNotAllowedError,
  resolveMagicLinkUrl,
} from '../services/magicLinkRedirect.js';
import { AuthenticatedRequest } from '../types/types.js';
import { hashDeviceFingerprint } from '../utils/utils.js';

/**
 * How the fifteen ephemeral endpoints answer when the pre-auth subject is a decoy.
 *
 * The rule each one follows: answer the way the endpoint answers for a real account in
 * the most ordinary state it could be in. A decoy's OTP send succeeds without sending,
 * because a real send succeeds. A decoy's OTP verify fails the way a wrong code fails,
 * because that is where a caller who guesses wrong ends up. Nothing here is a special
 * decoy status code, because a special status code is the oracle rewritten.
 *
 * Two properties every responder holds to:
 *
 * - **No decoy state.** A decoy is issued for any identifier a stranger can type, so
 *   nothing here stores a challenge, a link or a code. The auth event each responder
 *   records is the exception, and it is the one every request already writes.
 * - **No real handler.** `defineRoute` dispatches here instead of the controller, so the
 *   stand-in principal never reaches code that could persist it.
 *
 * Policy-dependent branches are reproduced rather than skipped. A deployment with
 * `email_otp` disabled answers `403 login_method_disabled` for every identifier, so a
 * decoy that returned success there would stand out immediately.
 */

function decoySubject(req: Request) {
  return (req as AuthenticatedRequest).user.id;
}

/**
 * The decoy behind this request. Rebuilt from the subject rather than carried, so it is
 * the same fiction the middleware produced and the same one `/login` shaped its answer
 * from.
 */
function decoyPrincipal(req: Request) {
  return decoyPrincipalForSubject(decoySubject(req));
}

async function logDecoy(req: Request, endpoint: string) {
  // Recorded so bulk probing is still visible to operators. `userId` is null because
  // there is no user; the subject is deliberately not written down, since it is derived
  // from an identifier that does not belong to anyone here.
  await AuthEventService.log({
    userId: null,
    type: 'login_failed',
    req,
    metadata: { reason: 'Decoy continuation', endpoint },
  });
}

/**
 * Mirrors `rejectDisabledLoginMethod` in the OTP controller and `rejectDisabledMagicLink`
 * in the magic link controller. Both answer 403 before looking at the account at all, so
 * a decoy has to reach the same answer from the same policy read.
 */
async function rejectDisabledMethod(method: LoginMethod, req: Request, res: Response) {
  const policy = await getLoginPolicy();

  if (isLoginMethodEnabled(policy, method)) {
    return false;
  }

  await AuthEventService.log({
    userId: null,
    type: 'login_failed',
    req,
    metadata: { reason: 'Login method disabled', method },
  });

  res.status(403).json({ error: 'login_method_disabled' });
  return true;
}

async function respondOtpSent(req: Request, res: Response, kind: 'otp_email' | 'otp_sms') {
  const authReq = req as AuthenticatedRequest;
  const subject = decoySubject(req);
  const useExternalDelivery = await canReturnExternalDelivery(req);

  await logDecoy(req, `otp:${kind}`);

  // A real account with no phone answers 400 here, and about half of decoys are shaped
  // without one so that a narrow login method list proves nothing. Those decoys have to
  // answer 400 too, or the shape that was hiding them becomes the thing that shows them.
  if (kind === 'otp_sms' && !authReq.user.phone) {
    return res.status(400).json({ error: 'Invalid data' });
  }

  const token = await signEphemeralToken(subject);

  return res.status(200).json({
    message: 'success',
    token,
    ...(useExternalDelivery
      ? {
          delivery: {
            kind,
            to: kind === 'otp_email' ? authReq.user.email : authReq.user.phone,
            token: decoyOtpFor(subject),
          },
        }
      : {}),
  });
}

export const decoySendEmailOtp = (req: Request, res: Response) =>
  respondOtpSent(req, res, 'otp_email');

export const decoySendPhoneOtp = (req: Request, res: Response) =>
  respondOtpSent(req, res, 'otp_sms');

export const decoySendLoginEmailOtp = async (req: Request, res: Response) => {
  if (await rejectDisabledMethod('email_otp', req, res)) {
    return;
  }

  return respondOtpSent(req, res, 'otp_email');
};

export const decoySendLoginPhoneOtp = async (req: Request, res: Response) => {
  if (await rejectDisabledMethod('phone_otp', req, res)) {
    return;
  }

  return respondOtpSent(req, res, 'otp_sms');
};

/**
 * A decoy has no stored code, so verification can only fail. It fails with the body a
 * real account gets for a code that did not match, which is the outcome a caller
 * guessing at a real account overwhelmingly lands on too.
 */
async function respondOtpVerifyFailed(req: Request, res: Response) {
  await logDecoy(req, 'otp:verify');

  return res.status(401).json({ error: 'Not allowed' });
}

export const decoyVerifyEmailOtp = respondOtpVerifyFailed;
export const decoyVerifyPhoneOtp = respondOtpVerifyFailed;

export const decoyVerifyLoginEmailOtp = async (req: Request, res: Response) => {
  if (await rejectDisabledMethod('email_otp', req, res)) {
    return;
  }

  return respondOtpVerifyFailed(req, res);
};

export const decoyVerifyLoginPhoneOtp = async (req: Request, res: Response) => {
  if (await rejectDisabledMethod('phone_otp', req, res)) {
    return;
  }

  return respondOtpVerifyFailed(req, res);
};

export const decoyRequestMagicLink = async (req: Request, res: Response) => {
  if (await rejectDisabledMethod('magic_link', req, res)) {
    return;
  }

  const authReq = req as AuthenticatedRequest;
  const useExternalDelivery = await canReturnExternalDelivery(req);

  await logDecoy(req, 'magic_link:request');

  const rawToken = decoyCredentialIdFor(decoySubject(req));

  // Both checks below answer 400 for a real account before anything is stored, and both
  // are reachable by choice: a caller picks the redirect it sends, and omitting a
  // User-Agent header is enough to trip the second. A decoy that skipped them would
  // answer 200 where a real account answers 400, which is a working oracle for the price
  // of one deliberately bad request.
  let magicLinkUrl: string;

  try {
    magicLinkUrl = await resolveMagicLinkUrl(rawToken, req.query.redirectUri as string | undefined);
  } catch (error) {
    if (error instanceof MagicLinkRedirectNotAllowedError) {
      return res.status(400).json({ error: 'Redirect URI is not allowed' });
    }

    throw error;
  }

  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  if (!ip_hash || !user_agent_hash) {
    return res.status(400).json({ error: 'Invalid device data' });
  }

  return res.json({
    message: 'If an account exists, a login link has been sent.',
    ...(useExternalDelivery
      ? {
          delivery: {
            kind: 'magic_link_email',
            to: authReq.user.email,
            token: rawToken,
            magicLinkUrl,
          },
        }
      : {}),
  });
};

/**
 * `204` is what a real account polls back for as long as nobody has clicked the link,
 * which for a decoy is always. The alternative states, `200` with a session and the
 * `403` device-binding mismatches, are all reachable only from a stored link.
 */
export const decoyPollMagicLink = async (req: Request, res: Response) => {
  if (await rejectDisabledMethod('magic_link', req, res)) {
    return;
  }

  await logDecoy(req, 'magic_link:poll');

  return res.status(204).end();
};

/**
 * Real registration options, minus the challenge record. Skipping `issueChallenge` keeps
 * the responder free of writes and costs nothing observable: the ceremony this returns
 * can never be completed anyway, and `/register/finish` answers with the same
 * "missing challenge" a real expired ceremony gets.
 *
 * The branches the real handler takes before it gets there are reproduced, because each
 * one a decoy skipped would be a request a caller could craft to tell the two apart.
 */
export const decoyStartWebAuthnRegistration = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const principal = decoyPrincipal(req);
  const subject = principal.id;
  const { requestPrf = false, attachment } = req.query as {
    requestPrf?: boolean;
    attachment?: WebAuthnAuthenticatorAttachment;
  };
  const { app_name, rpid, authenticator_policy } = await getSystemConfig();
  const pinnedAttachment =
    authenticator_policy.attachment === 'any' ? null : authenticator_policy.attachment;

  await logDecoy(req, 'webauthn:register_start');

  if (pinnedAttachment && attachment && attachment !== pinnedAttachment) {
    return res.status(400).json({ error: 'attachment_not_allowed' });
  }

  const options = await generateRegistrationOptions({
    rpName: app_name,
    rpID: rpid,
    userName: authReq.user.email,
    timeout: 60000,
    attestationType: authenticator_policy.attestation,
    supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
    // A real account's enrolled credentials go here, so an always-empty list would say
    // "this subject has no passkey" to anyone who looked.
    excludeCredentials: principal.hasPasskey
      ? [{ id: decoyCredentialIdFor(subject), transports: principal.transports }]
      : [],
    authenticatorSelection: {
      userVerification: authenticator_policy.userVerification,
      residentKey: 'preferred',
      ...((pinnedAttachment ?? attachment)
        ? { authenticatorAttachment: pinnedAttachment ?? attachment }
        : {}),
    },
    extensions: buildPrfRegistrationExtensions(requestPrf),
  });

  return res.json(options);
};

export const decoyFinishWebAuthnRegistration = async (req: Request, res: Response) => {
  await logDecoy(req, 'webauthn:register_finish');

  return res.status(403).json({ error: 'Missing challenge' });
};

/**
 * A plausible assertion challenge for a subject with no credentials.
 *
 * The fabricated allow-list matters. A real account with no passkey answers `401`, so
 * returning a challenge unconditionally would separate "unknown identifier" from "account
 * with a passkey", which is most accounts reaching this endpoint at all.
 *
 * It matters just as much that the refusals are reproduced. The real handler filters the
 * account's credentials by the requested `credentialId` and `prf` and answers
 * `401 Credentials not found` when nothing survives, so a caller can ask for a credential
 * id that cannot exist and read the answer: every real account refuses, and a decoy that
 * always returned a challenge would accept. That is a complete oracle two requests long,
 * so the decoy's single fabricated credential is filtered the same way.
 *
 * The refusal is `res.send`, not `res.json`. A JSON body here would differ in content
 * type from the real one.
 */
export const decoyStartWebAuthnLogin = async (req: Request, res: Response) => {
  const principal = decoyPrincipal(req);
  const subject = principal.id;
  const { credentialId, prf } = req.body ?? {};
  const credential = { id: decoyCredentialIdFor(subject), transports: principal.transports };
  const { rpid, authenticator_policy } = await getSystemConfig();

  await logDecoy(req, 'webauthn:login_start');

  const survives =
    principal.hasPasskey &&
    (!credentialId || credentialId === credential.id) &&
    (!prf || principal.prfCapable);

  if (!survives) {
    return res.status(401).send('Credentials not found');
  }

  const options = await generateAuthenticationOptions({
    allowCredentials: [credential],
    userVerification: authenticator_policy.userVerification,
    timeout: 60000,
    rpID: rpid,
    extensions: buildPrfAuthenticationExtensions(prf),
  });

  return res.json(options);
};

export const decoyFinishWebAuthnLogin = async (req: Request, res: Response) => {
  await logDecoy(req, 'webauthn:login_finish');

  return res.status(401).json({ error: 'Authentication failed.' });
};

export const decoyVerifyTotpLogin = async (req: Request, res: Response) => {
  await logDecoy(req, 'totp:verify_login');

  return res.status(401).json({ error: 'totp_verification_failed' });
};
