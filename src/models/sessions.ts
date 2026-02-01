/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface SessionAttributes {
  id: string;
  userId: string;
  infraId?: string | null;
  mode: 'web' | 'server';
  refreshTokenHash: string;
  userAgent?: string | null;
  ipAddress?: string | null;
  deviceName?: string | null;
  lastUsedAt: Date;
  expiresAt: Date;
  idleExpiresAt: Date;
  replacedBySessionId?: string | null;
  revokedAt?: Date | null;
  revokedReason?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type SessionCreationAttributes = Optional<
  SessionAttributes,
  'id' | 'replacedBySessionId' | 'revokedAt' | 'revokedReason' | 'deviceName' | 'lastUsedAt'
>;

export class Session
  extends Model<SessionAttributes, SessionCreationAttributes>
  implements SessionAttributes
{
  declare id: string;
  declare userId: string;
  declare infraId: string | null;
  declare mode: 'web' | 'server';
  declare refreshTokenHash: string;
  declare userAgent: string | null;
  declare ipAddress: string | null;
  declare deviceName: string | null;
  declare lastUsedAt: Date;
  declare expiresAt: Date;
  declare idleExpiresAt: Date;
  declare replacedBySessionId: string | null;
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
      mode: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          isIn: [['web', 'server']],
        },
      },
      refreshTokenHash: {
        type: DataTypes.TEXT,
        allowNull: false,
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
      replacedBySessionId: {
        type: DataTypes.UUID,
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
