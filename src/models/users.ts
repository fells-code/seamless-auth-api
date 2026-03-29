/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Association, DataTypes, Model, Sequelize } from 'sequelize';

import type { Credential } from './credentials.js';

export interface UserAttributes {
  id?: string;
  email: string;
  phone: string;
  roles?: string[];
  revoked?: boolean;
  emailVerificationToken?: string | null;
  emailVerificationTokenExpiry?: number | null;
  phoneVerificationToken?: string | null;
  phoneVerificationTokenExpiry?: number | null;
  emailVerified?: boolean;
  phoneVerified?: boolean;
  verified?: boolean;
  challenge?: string | null;
  lastLogin?: Date;
  createdAt?: Date;
  updatedAt?: Date;
  credentials?: Credential[];
}

export class User extends Model<UserAttributes> implements UserAttributes {
  declare id: string;
  declare email: string;
  declare phone: string;
  declare revoked: boolean;
  declare emailVerificationToken: string | null;
  declare emailVerificationTokenExpiry: number | null;
  declare phoneVerificationToken: string | null;
  declare phoneVerificationTokenExpiry: number | null;
  declare emailVerified: boolean;
  declare phoneVerified: boolean;
  declare verified: boolean;
  declare challenge: string | null;
  declare roles?: string[];
  declare lastLogin?: Date;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
  declare readonly credentials?: Credential[];

  public static associations: {
    credentials: Association<User, Credential>;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    User.hasMany(models.Credential, {
      foreignKey: 'userId',
      onDelete: 'CASCADE',
      as: 'credentials',
    });
  }
}

const initializeUserModel = (sequelize: Sequelize) => {
  User.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      phone: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      roles: {
        type: DataTypes.ARRAY(DataTypes.STRING),
        allowNull: false,
        defaultValue: [],
      },
      emailVerificationToken: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      emailVerificationTokenExpiry: {
        type: DataTypes.BIGINT,
        allowNull: true,
      },
      phoneVerificationToken: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      phoneVerificationTokenExpiry: {
        type: DataTypes.BIGINT,
        allowNull: true,
      },
      revoked: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      verified: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      emailVerified: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      phoneVerified: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      challenge: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      lastLogin: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'User',
      tableName: 'users',
      underscored: true,
    },
  );

  return User;
};

export default initializeUserModel;
