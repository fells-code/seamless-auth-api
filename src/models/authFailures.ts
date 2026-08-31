/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Sequelize } from 'sequelize';

export interface AuthFailureAttributes {
  id?: string;
  userId: string;
  type: string;
  occurredAt?: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

/**
 * A failed authentication attempt, counted by the lockout policy.
 *
 * Deliberately separate from `AuthEvent`. The audit trail swallows write errors
 * so that recording an event can never fail the operation it describes, which is
 * the right posture for a record and the wrong one for a security control that
 * is derived from it.
 */
export class AuthFailure extends Model<AuthFailureAttributes> implements AuthFailureAttributes {
  declare id: string;
  declare userId: string;
  declare type: string;
  declare occurredAt: Date;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeAuthFailureModel = (sequelize: Sequelize) => {
  AuthFailure.init(
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
      type: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      occurredAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW,
      },
    },
    {
      sequelize,
      modelName: 'AuthFailure',
      tableName: 'auth_failures',
      underscored: true,
    },
  );

  return AuthFailure;
};

export default initializeAuthFailureModel;
