/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { OidcAuthMethodRecord } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export type SessionAuthMethod = OidcAuthMethodRecord;

export interface SessionAttributes {
  id: string;
  userId: string;
  infraId?: string | null;
  organizationId?: string | null;
  mode: 'server';
  refreshTokenLookup?: string | null;
  userAgent?: string | null;
  ipAddress?: string | null;
  deviceName?: string | null;
  lastUsedAt: Date;
  expiresAt: Date;
  idleExpiresAt: Date;
  chainStartedAt?: Date | null;
  stepUpVerifiedAt?: Date | null;
  stepUpMethod?: string | null;
  recovery?: boolean;
  authMethods?: SessionAuthMethod[];
  authTime?: Date | null;
  /** What the `pre_token` login hook added, kept so a refresh never calls the hook. */
  hookClaims?: Record<string, unknown> | null;
  replacedBySessionId?: string | null;
  parentSessionId?: string | null;
  exchangeClientId?: string | null;
  exchangeGrantType?: string | null;
  revokedAt?: Date | null;
  revokedReason?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type SessionCreationAttributes = Optional<
  SessionAttributes,
  | 'id'
  | 'replacedBySessionId'
  | 'revokedAt'
  | 'revokedReason'
  | 'deviceName'
  | 'lastUsedAt'
  | 'stepUpVerifiedAt'
  | 'stepUpMethod'
  | 'authMethods'
  | 'authTime'
  | 'hookClaims'
  | 'parentSessionId'
  | 'exchangeClientId'
  | 'exchangeGrantType'
>;

export class Session
  extends Model<SessionAttributes, SessionCreationAttributes>
  implements SessionAttributes
{
  declare id: string;
  declare userId: string;
  declare infraId: string | null;
  declare organizationId: string | null;
  declare mode: 'server';
  declare refreshTokenLookup: string | null;
  declare userAgent: string | null;
  declare ipAddress: string | null;
  declare deviceName: string | null;
  declare lastUsedAt: Date;
  declare expiresAt: Date;
  declare idleExpiresAt: Date;
  declare chainStartedAt: Date | null;
  declare stepUpVerifiedAt: Date | null;
  declare stepUpMethod: string | null;
  declare recovery: boolean;
  declare authMethods: SessionAuthMethod[];
  declare authTime: Date | null;
  declare hookClaims: Record<string, unknown> | null;
  declare replacedBySessionId: string | null;
  declare parentSessionId: string | null;
  declare exchangeClientId: string | null;
  declare exchangeGrantType: string | null;
  declare revokedAt: Date | null;
  declare revokedReason: string | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeSessionModel = (sequelize: Sequelize) => {
  Session.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      infraId: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      organizationId: {
        type: DataTypes.UUID,
        allowNull: true,
      },
      mode: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          isIn: [['server']],
        },
      },
      refreshTokenLookup: {
        type: DataTypes.STRING(64),
        allowNull: true,
      },
      userAgent: DataTypes.TEXT,
      ipAddress: DataTypes.STRING,
      deviceName: DataTypes.STRING,
      lastUsedAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW,
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      idleExpiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      chainStartedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      stepUpVerifiedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      stepUpMethod: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      // A session a recovery issued, restricted to enrolling a new factor until one is.
      recovery: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      // What the sign-in and any step-ups proved, from which provider acr and amr are derived.
      authMethods: {
        type: DataTypes.JSONB,
        allowNull: false,
        defaultValue: [],
      },
      authTime: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      hookClaims: {
        type: DataTypes.JSONB,
        allowNull: true,
      },
      replacedBySessionId: {
        type: DataTypes.UUID,
        allowNull: true,
      },
      // A session a token exchange issued (ADR 0003): the provider sign-in it ends with, the
      // client that exchanged, and the grant behind the sign-in. Carried across rotation.
      parentSessionId: {
        type: DataTypes.UUID,
        allowNull: true,
      },
      exchangeClientId: {
        type: DataTypes.STRING(255),
        allowNull: true,
      },
      exchangeGrantType: {
        type: DataTypes.STRING(255),
        allowNull: true,
      },
      revokedAt: DataTypes.DATE,
      revokedReason: DataTypes.STRING,
    },
    {
      sequelize,
      tableName: 'sessions',
      modelName: 'Session',
    },
  );
  return Session;
};

export default initializeSessionModel;
