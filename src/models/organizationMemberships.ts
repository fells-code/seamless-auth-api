/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Association, DataTypes, Model, Optional, Sequelize } from 'sequelize';

import type { Organization } from './organizations.js';
import type { User } from './users.js';

export interface OrganizationMembershipAttributes {
  id?: string;
  organizationId: string;
  userId: string;
  roles?: string[];
  scopes?: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

type OrganizationMembershipCreationAttributes = Optional<
  OrganizationMembershipAttributes,
  'id' | 'roles' | 'scopes' | 'createdAt' | 'updatedAt'
>;

export class OrganizationMembership
  extends Model<OrganizationMembershipAttributes, OrganizationMembershipCreationAttributes>
  implements OrganizationMembershipAttributes
{
  declare id: string;
  declare organizationId: string;
  declare userId: string;
  declare roles: string[];
  declare scopes: string[];
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;

  public static associations: {
    organization: Association<OrganizationMembership, Organization>;
    user: Association<OrganizationMembership, User>;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static associate(models: any) {
    OrganizationMembership.belongsTo(models.Organization, {
      foreignKey: 'organizationId',
      as: 'organization',
      onDelete: 'CASCADE',
    });

    OrganizationMembership.belongsTo(models.User, {
      foreignKey: 'userId',
      as: 'user',
      onDelete: 'CASCADE',
    });
  }
}

const initializeOrganizationMembershipModel = (sequelize: Sequelize) => {
  OrganizationMembership.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      organizationId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      roles: {
        type: DataTypes.JSON,
        allowNull: false,
        defaultValue: ['member'],
      },
      scopes: {
        type: DataTypes.JSON,
        allowNull: false,
        defaultValue: [],
      },
    },
    {
      sequelize,
      modelName: 'OrganizationMembership',
      tableName: 'organization_memberships',
      underscored: true,
      indexes: [
        {
          unique: true,
          fields: ['organization_id', 'user_id'],
        },
      ],
    },
  );

  return OrganizationMembership;
};

export default initializeOrganizationMembershipModel;
