/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  CreationOptional,
  DataTypes,
  InferAttributes,
  InferCreationAttributes,
  Model,
  Sequelize,
} from 'sequelize';

export class BootstrapInvite extends Model<
  InferAttributes<BootstrapInvite>,
  InferCreationAttributes<BootstrapInvite>
> {
  declare id: CreationOptional<string>;
  declare email: string;
  declare role: 'admin';
  declare tokenHash: string;
  declare expiresAt: Date;
  declare consumedAt: Date | null;
  declare createdBy: string;
  declare createdIp: string | null;
  declare createdUserAgent: string | null;
  declare lastSentAt: Date | null;
  declare attemptCount: CreationOptional<number>;
  declare createdAt: CreationOptional<Date>;
  declare updatedAt: CreationOptional<Date>;
}

const initializeBootstrapInviteModel = (sequelize: Sequelize) => {
  BootstrapInvite.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      email: {
        type: DataTypes.STRING(320),
        allowNull: false,
        validate: {
          isEmail: true,
        },
      },
      role: {
        type: DataTypes.ENUM('admin'),
        allowNull: false,
        defaultValue: 'admin',
      },
      tokenHash: {
        type: DataTypes.STRING(255),
        allowNull: false,
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      consumedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      createdBy: {
        type: DataTypes.STRING(64),
        allowNull: false,
        defaultValue: 'bootstrap',
      },
      createdIp: {
        type: DataTypes.STRING(64),
        allowNull: true,
      },
      createdUserAgent: {
        type: DataTypes.TEXT,
        allowNull: true,
      },
      lastSentAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      attemptCount: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      createdAt: DataTypes.DATE,
      updatedAt: DataTypes.DATE,
    },
    {
      sequelize,
      modelName: 'BootstrapInvite',
      tableName: 'bootstrap_invites',
      underscored: true,
      indexes: [
        { fields: ['email'] },
        { fields: ['expires_at'] },
        { fields: ['consumed_at'] },
        { unique: true, fields: ['token_hash'] },
      ],
    },
  );
  return BootstrapInvite;
};

export default initializeBootstrapInviteModel;
