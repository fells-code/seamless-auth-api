/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthenticatorTransportFuture, CredentialDeviceType } from '@simplewebauthn/server';
import { DataTypes, Model, Sequelize } from 'sequelize';

import type { User } from './users.js';

export class Credential extends Model {
  declare id: Base64URLString;
  declare userId: string;
  declare publicKey: Uint8Array;
  declare counter: number;
  declare transports?: AuthenticatorTransportFuture[];
  declare deviceType: CredentialDeviceType;
  declare backedup: boolean;
  declare prfCapable: boolean;

  declare friendlyName: string | null;
  declare lastUsedAt: Date | null;
  declare platform: string | null;
  declare browser: string | null;
  declare deviceInfo: string | null;

  declare readonly user?: User;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    Credential.belongsTo(models.User, {
      foreignKey: 'userId',
      onDelete: 'CASCADE',
      as: 'user',
    });
  }
}

export default (sequelize: Sequelize) => {
  Credential.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      publicKey: {
        type: DataTypes.BLOB,
        allowNull: false,
      },
      counter: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      transports: {
        type: DataTypes.JSON,
      },
      backedup: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      prfCapable: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      deviceType: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      friendlyName: {
        type: DataTypes.STRING,
        allowNull: true,
        defaultValue: null,
      },
      lastUsedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      platform: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      browser: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      deviceInfo: {
        type: DataTypes.STRING,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'Credential',
      tableName: 'credentials',
      timestamps: true,
    },
  );

  return Credential;
};
