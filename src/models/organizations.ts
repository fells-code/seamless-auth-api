/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Association, DataTypes, Model, Optional, Sequelize } from 'sequelize';

import type { OrganizationMembership } from './organizationMemberships.js';
import type { User } from './users.js';

export interface OrganizationAttributes {
  id?: string;
  name: string;
  slug: string;
  createdByUserId?: string | null;
  metadata?: Record<string, unknown> | null;
  createdAt?: Date;
  updatedAt?: Date;
  memberships?: OrganizationMembership[];
}

type OrganizationCreationAttributes = Optional<
  OrganizationAttributes,
  'id' | 'createdByUserId' | 'metadata' | 'createdAt' | 'updatedAt' | 'memberships'
>;

export class Organization
  extends Model<OrganizationAttributes, OrganizationCreationAttributes>
  implements OrganizationAttributes
{
  declare id: string;
  declare name: string;
  declare slug: string;
  declare createdByUserId: string | null;
  declare metadata: Record<string, unknown> | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
  declare readonly memberships?: OrganizationMembership[];

  public static associations: {
    memberships: Association<Organization, OrganizationMembership>;
    createdBy: Association<Organization, User>;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    Organization.hasMany(models.OrganizationMembership, {
      foreignKey: 'organizationId',
      onDelete: 'CASCADE',
      as: 'memberships',
    });

    Organization.belongsTo(models.User, {
      foreignKey: 'createdByUserId',
      as: 'createdBy',
    });
  }
}

const initializeOrganizationModel = (sequelize: Sequelize) => {
  Organization.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      slug: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      createdByUserId: {
        type: DataTypes.UUID,
        allowNull: true,
      },
      metadata: {
        type: DataTypes.JSON,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'Organization',
      tableName: 'organizations',
      underscored: true,
    },
  );

  return Organization;
};

export default initializeOrganizationModel;
