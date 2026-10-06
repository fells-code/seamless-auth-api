/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Sequelize } from 'sequelize';

import type { User } from './users.js';

export interface UserExternalIdAttributes {
  id?: string;
  userId: string;
  source: string;
  externalId: string;
  createdAt?: Date;
  updatedAt?: Date;
}

export class UserExternalId
  extends Model<UserExternalIdAttributes>
  implements UserExternalIdAttributes
{
  declare id: string;
  declare userId: string;
  declare source: string;
  declare externalId: string;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
  declare readonly user?: User;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    UserExternalId.belongsTo(models.User, {
      foreignKey: 'userId',
      onDelete: 'CASCADE',
      as: 'user',
    });
  }
}

const initializeUserExternalIdModel = (sequelize: Sequelize) => {
  UserExternalId.init(
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
      source: {
        type: DataTypes.STRING(64),
        allowNull: false,
      },
      externalId: {
        type: DataTypes.STRING(255),
        allowNull: false,
      },
    },
    {
      sequelize,
      modelName: 'UserExternalId',
      tableName: 'user_external_ids',
      underscored: true,
      indexes: [
        {
          unique: true,
          fields: ['source', 'external_id'],
        },
        {
          unique: true,
          fields: ['user_id', 'source'],
        },
      ],
    },
  );

  return UserExternalId;
};

export default initializeUserExternalIdModel;
