/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface OrganizationRoleAttributes {
  name: string;
  description?: string | null;
  /** `owner`, `admin` and `member`, which the organization routes depend on. */
  builtIn?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

type OrganizationRoleCreationAttributes = Optional<
  OrganizationRoleAttributes,
  'description' | 'builtIn' | 'createdAt' | 'updatedAt'
>;

export class OrganizationRole
  extends Model<OrganizationRoleAttributes, OrganizationRoleCreationAttributes>
  implements OrganizationRoleAttributes
{
  declare name: string;
  declare description: string | null;
  declare builtIn: boolean;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeOrganizationRoleModel = (sequelize: Sequelize) => {
  OrganizationRole.init(
    {
      name: { type: DataTypes.STRING(80), primaryKey: true },
      description: { type: DataTypes.TEXT, allowNull: true },
      builtIn: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    },
    {
      sequelize,
      tableName: 'organization_roles',
      modelName: 'OrganizationRole',
    },
  );
  return OrganizationRole;
};

export default initializeOrganizationRoleModel;
