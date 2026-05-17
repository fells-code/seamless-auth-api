/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Association, DataTypes, Model, Optional, Sequelize } from 'sequelize';

import type { User } from './users.js';

export interface TotpCredentialAttributes {
  id: string;
  userId: string;
  secretCiphertext: string;
  secretIv: string;
  secretTag: string;
  issuer: string;
  accountName: string;
  enabled: boolean;
  verifiedAt?: Date | null;
  lastUsedAt?: Date | null;
  lastUsedCounter?: number | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type TotpCredentialCreationAttributes = Optional<
  TotpCredentialAttributes,
  'id' | 'enabled' | 'verifiedAt' | 'lastUsedAt' | 'lastUsedCounter'
>;

export class TotpCredential
  extends Model<TotpCredentialAttributes, TotpCredentialCreationAttributes>
  implements TotpCredentialAttributes
{
  declare id: string;
  declare userId: string;
  declare secretCiphertext: string;
  declare secretIv: string;
  declare secretTag: string;
  declare issuer: string;
  declare accountName: string;
  declare enabled: boolean;
  declare verifiedAt: Date | null;
  declare lastUsedAt: Date | null;
  declare lastUsedCounter: number | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;

  public static associations: {
    user: Association<TotpCredential, User>;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    TotpCredential.belongsTo(models.User, {
      foreignKey: 'userId',
      as: 'user',
    });
  }
}

const initializeTotpCredentialModel = (sequelize: Sequelize) => {
  TotpCredential.init(
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
      secretCiphertext: {
        type: DataTypes.TEXT,
        allowNull: false,
      },
      secretIv: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      secretTag: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      issuer: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      accountName: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      verifiedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      lastUsedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      lastUsedCounter: {
        type: DataTypes.BIGINT,
        allowNull: true,
      },
    },
    {
      sequelize,
      tableName: 'totp_credentials',
      modelName: 'TotpCredential',
    },
  );

  return TotpCredential;
};

export default initializeTotpCredentialModel;
