/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface PermissionAttributes {
  id?: string;
  name: string;
  description?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type PermissionCreationAttributes = Optional<
  PermissionAttributes,
  'id' | 'description' | 'createdAt' | 'updatedAt'
>;

export class Permission
  extends Model<PermissionAttributes, PermissionCreationAttributes>
  implements PermissionAttributes
{
  declare id: string;
  declare name: string;
  declare description: string | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializePermissionModel = (sequelize: Sequelize) => {
  Permission.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      name: { type: DataTypes.STRING(80), allowNull: false, unique: true },
      description: { type: DataTypes.TEXT, allowNull: true },
    },
    {
      sequelize,
      tableName: 'permissions',
      modelName: 'Permission',
    },
  );
  return Permission;
};

export default initializePermissionModel;
