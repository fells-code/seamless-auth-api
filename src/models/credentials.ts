/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import {
  AuthenticatorTransportFuture,
  Base64URLString,
  CredentialDeviceType,
} from '@simplewebauthn/server/script/types';
import { DataTypes, Model, Sequelize } from 'sequelize';

import type { User } from './users';

export class Credential extends Model {
  declare id: Base64URLString;
  public userId!: string;
  public publicKey!: Uint8Array;
  public counter!: number;
  public transports?: AuthenticatorTransportFuture[];
  public deviceType!: CredentialDeviceType;
  public backedup!: boolean;

  public friendlyName!: string | null;
  public lastUsedAt!: Date | null;
  public platform!: string | null;
  public browser!: string | null;
  public deviceInfo!: string | null;

  public readonly user?: User;

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
