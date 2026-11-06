/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { RoleKind } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface RolePermissionAttributes {
  roleKind: RoleKind;
  roleName: string;
  permissionName: string;
  /** The admin who made the mapping. */
  createdBy?: string | null;
  createdAt?: Date;
}

type RolePermissionCreationAttributes = Optional<
  RolePermissionAttributes,
  'createdBy' | 'createdAt'
>;

export class RolePermission
  extends Model<RolePermissionAttributes, RolePermissionCreationAttributes>
  implements RolePermissionAttributes
{
  declare roleKind: RoleKind;
  declare roleName: string;
  declare permissionName: string;
  declare createdBy: string | null;
  declare readonly createdAt: Date;
}

const initializeRolePermissionModel = (sequelize: Sequelize) => {
  RolePermission.init(
    {
      roleKind: { type: DataTypes.STRING(20), primaryKey: true },
      roleName: { type: DataTypes.STRING(80), primaryKey: true },
      permissionName: { type: DataTypes.STRING(80), primaryKey: true },
      createdBy: { type: DataTypes.UUID, allowNull: true },
    },
    {
      sequelize,
      tableName: 'role_permissions',
      modelName: 'RolePermission',
      updatedAt: false,
    },
  );
  return RolePermission;
};

export default initializeRolePermissionModel;
