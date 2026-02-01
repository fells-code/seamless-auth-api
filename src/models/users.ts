/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Association, DataTypes, Model, Sequelize } from 'sequelize';

import type { Credential } from './credentials';

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
  public id!: string;
  public email!: string;
  public phone!: string;
  public revoked!: boolean;
  public emailVerificationToken!: string | null;
  public emailVerificationTokenExpiry!: number | null;
  public phoneVerificationToken!: string | null;
  public phoneVerificationTokenExpiry!: number | null;
  public emailVerified!: boolean;
  public phoneVerified!: boolean;
  public verified!: boolean;
  public challenge!: string | null;
  public roles?: string[];
  public lastLogin?: Date;
  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;
  public readonly credentials?: Credential[];

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
