/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { PolicyVersionSource } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface PolicyVersionAttributes {
  version: number;
  policy: unknown;
  source: PolicyVersionSource;
  rolledBackTo?: number | null;
  createdBy?: string | null;
  createdAt?: Date;
}

type PolicyVersionCreationAttributes = Optional<
  PolicyVersionAttributes,
  'rolledBackTo' | 'createdBy' | 'createdAt'
>;

export class PolicyVersion
  extends Model<PolicyVersionAttributes, PolicyVersionCreationAttributes>
  implements PolicyVersionAttributes
{
  declare version: number;
  declare policy: unknown;
  declare source: PolicyVersionSource;
  declare rolledBackTo: number | null;
  declare createdBy: string | null;
  declare readonly createdAt: Date;
}

const initializePolicyVersionModel = (sequelize: Sequelize) => {
  PolicyVersion.init(
    {
      version: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        allowNull: false,
      },
      policy: {
        type: DataTypes.JSONB,
        allowNull: false,
      },
      source: {
        type: DataTypes.STRING(16),
        allowNull: false,
      },
      rolledBackTo: {
        type: DataTypes.INTEGER,
        allowNull: true,
      },
      createdBy: {
        type: DataTypes.UUID,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'PolicyVersion',
      tableName: 'policy_versions',
      underscored: true,
      timestamps: true,
      updatedAt: false,
    },
  );

  return PolicyVersion;
};

export default initializePolicyVersionModel;
