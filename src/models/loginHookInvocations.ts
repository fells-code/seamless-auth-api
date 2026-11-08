/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { CalloutFailure, LoginHookOutcome, LoginHookTrigger } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface LoginHookInvocationAttributes {
  /** The `webhook-id` header and the call's `id`. */
  id: string;
  trigger: LoginHookTrigger;
  userId: string | null;
  outcome: LoginHookOutcome;
  failure: CalloutFailure | null;
  statusCode: number | null;
  durationMs: number;
  createdAt?: Date;
  updatedAt?: Date;
}

type LoginHookInvocationCreationAttributes = Optional<
  LoginHookInvocationAttributes,
  'userId' | 'failure' | 'statusCode' | 'createdAt' | 'updatedAt'
>;

export class LoginHookInvocation
  extends Model<LoginHookInvocationAttributes, LoginHookInvocationCreationAttributes>
  implements LoginHookInvocationAttributes
{
  declare id: string;
  declare trigger: LoginHookTrigger;
  declare userId: string | null;
  declare outcome: LoginHookOutcome;
  declare failure: CalloutFailure | null;
  declare statusCode: number | null;
  declare durationMs: number;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeLoginHookInvocationModel = (sequelize: Sequelize) => {
  LoginHookInvocation.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true, allowNull: false },
      trigger: { type: DataTypes.STRING(20), allowNull: false },
      userId: { type: DataTypes.UUID, allowNull: true },
      outcome: { type: DataTypes.STRING(20), allowNull: false },
      failure: { type: DataTypes.STRING(32), allowNull: true },
      statusCode: { type: DataTypes.INTEGER, allowNull: true },
      durationMs: { type: DataTypes.INTEGER, allowNull: false },
    },
    {
      sequelize,
      tableName: 'login_hook_invocations',
      modelName: 'LoginHookInvocation',
    },
  );
  return LoginHookInvocation;
};

export default initializeLoginHookInvocationModel;
