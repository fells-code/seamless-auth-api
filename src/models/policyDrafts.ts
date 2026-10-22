/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

/** The migration constrains the table to this one row. */
export const POLICY_DRAFT_ID = 1;

export interface PolicyDraftAttributes {
  id: number;
  policy: unknown;
  basedOnVersion: number;
  createdBy?: string | null;
  updatedBy?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type PolicyDraftCreationAttributes = Optional<
  PolicyDraftAttributes,
  'createdBy' | 'updatedBy' | 'createdAt' | 'updatedAt'
>;

export class PolicyDraft
  extends Model<PolicyDraftAttributes, PolicyDraftCreationAttributes>
  implements PolicyDraftAttributes
{
  declare id: number;
  declare policy: unknown;
  declare basedOnVersion: number;
  declare createdBy: string | null;
  declare updatedBy: string | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializePolicyDraftModel = (sequelize: Sequelize) => {
  PolicyDraft.init(
    {
      id: {
        type: DataTypes.SMALLINT,
        primaryKey: true,
        allowNull: false,
        defaultValue: POLICY_DRAFT_ID,
      },
      policy: {
        type: DataTypes.JSONB,
        allowNull: false,
      },
      basedOnVersion: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      createdBy: {
        type: DataTypes.UUID,
        allowNull: true,
      },
      updatedBy: {
        type: DataTypes.UUID,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'PolicyDraft',
      tableName: 'policy_drafts',
      underscored: true,
      timestamps: true,
    },
  );

  return PolicyDraft;
};

export default initializePolicyDraftModel;
