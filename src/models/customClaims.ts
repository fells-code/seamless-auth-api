/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { CustomClaimSourceKind } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface CustomClaimAttributes {
  sourceKind: CustomClaimSourceKind;
  /** A role name, or an OpenID Provider client id. */
  sourceName: string;
  claims: Record<string, unknown>;
  createdAt?: Date;
  updatedAt?: Date;
}

type CustomClaimCreationAttributes = Optional<CustomClaimAttributes, 'createdAt' | 'updatedAt'>;

export class CustomClaim
  extends Model<CustomClaimAttributes, CustomClaimCreationAttributes>
  implements CustomClaimAttributes
{
  declare sourceKind: CustomClaimSourceKind;
  declare sourceName: string;
  declare claims: Record<string, unknown>;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeCustomClaimModel = (sequelize: Sequelize) => {
  CustomClaim.init(
    {
      sourceKind: { type: DataTypes.STRING(32), primaryKey: true, allowNull: false },
      sourceName: { type: DataTypes.STRING(200), primaryKey: true, allowNull: false },
      claims: { type: DataTypes.JSONB, allowNull: false, defaultValue: {} },
    },
    {
      sequelize,
      tableName: 'custom_claims',
      modelName: 'CustomClaim',
    },
  );
  return CustomClaim;
};

export default initializeCustomClaimModel;
