/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export type WebAuthnChallengePurpose = 'registration' | 'authentication' | 'step_up';

export interface WebAuthnChallengeAttributes {
  id: string;
  userId: string;
  purpose: WebAuthnChallengePurpose;
  challenge: string;
  context?: Record<string, unknown> | null;
  expiresAt: Date;
  consumedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type WebAuthnChallengeCreationAttributes = Optional<
  WebAuthnChallengeAttributes,
  'id' | 'context' | 'consumedAt' | 'createdAt' | 'updatedAt'
>;

export class WebAuthnChallenge
  extends Model<WebAuthnChallengeAttributes, WebAuthnChallengeCreationAttributes>
  implements WebAuthnChallengeAttributes
{
  declare id: string;
  declare userId: string;
  declare purpose: WebAuthnChallengePurpose;
  declare challenge: string;
  declare context: Record<string, unknown> | null;
  declare expiresAt: Date;
  declare consumedAt: Date | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    WebAuthnChallenge.belongsTo(models.User, {
      foreignKey: 'userId',
      onDelete: 'CASCADE',
      as: 'user',
    });
  }
}

const initializeWebAuthnChallengeModel = (sequelize: Sequelize) => {
  WebAuthnChallenge.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      purpose: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      challenge: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      context: {
        type: DataTypes.JSONB,
        allowNull: true,
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      consumedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'WebAuthnChallenge',
      tableName: 'webauthn_challenges',
      underscored: true,
      timestamps: true,
    },
  );

  return WebAuthnChallenge;
};

export default initializeWebAuthnChallengeModel;
