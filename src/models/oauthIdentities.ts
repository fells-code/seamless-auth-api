/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Sequelize } from 'sequelize';

import type { User } from './users.js';

export interface OAuthIdentityAttributes {
  id?: string;
  userId: string;
  providerId: string;
  providerSubject: string;
  email: string;
  profile?: Record<string, unknown> | null;
  createdAt?: Date;
  updatedAt?: Date;
}

export class OAuthIdentity
  extends Model<OAuthIdentityAttributes>
  implements OAuthIdentityAttributes
{
  declare id: string;
  declare userId: string;
  declare providerId: string;
  declare providerSubject: string;
  declare email: string;
  declare profile: Record<string, unknown> | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
  declare readonly user?: User;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    OAuthIdentity.belongsTo(models.User, {
      foreignKey: 'userId',
      onDelete: 'CASCADE',
      as: 'user',
    });
  }
}

const initializeOAuthIdentityModel = (sequelize: Sequelize) => {
  OAuthIdentity.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      providerId: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      providerSubject: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      profile: {
        type: DataTypes.JSONB,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'OAuthIdentity',
      tableName: 'oauth_identities',
      underscored: true,
      indexes: [
        {
          unique: true,
          fields: ['provider_id', 'provider_subject'],
        },
        {
          fields: ['user_id'],
        },
      ],
    },
  );

  return OAuthIdentity;
};

export default initializeOAuthIdentityModel;
