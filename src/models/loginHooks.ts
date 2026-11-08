/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { LoginHookFailureMode, LoginHookTrigger } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface LoginHookAttributes {
  trigger: LoginHookTrigger;
  url: string;
  timeoutMs: number;
  failureMode: LoginHookFailureMode;
  enabled: boolean;
  secretCiphertext: string;
  secretIv: string;
  secretTag: string;
  previousSecretCiphertext: string | null;
  previousSecretIv: string | null;
  previousSecretTag: string | null;
  previousSecretExpiresAt: Date | null;
  createdBy: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type LoginHookCreationAttributes = Optional<
  LoginHookAttributes,
  | 'previousSecretCiphertext'
  | 'previousSecretIv'
  | 'previousSecretTag'
  | 'previousSecretExpiresAt'
  | 'createdBy'
  | 'createdAt'
  | 'updatedAt'
>;

export class LoginHook
  extends Model<LoginHookAttributes, LoginHookCreationAttributes>
  implements LoginHookAttributes
{
  declare trigger: LoginHookTrigger;
  declare url: string;
  declare timeoutMs: number;
  declare failureMode: LoginHookFailureMode;
  declare enabled: boolean;
  declare secretCiphertext: string;
  declare secretIv: string;
  declare secretTag: string;
  declare previousSecretCiphertext: string | null;
  declare previousSecretIv: string | null;
  declare previousSecretTag: string | null;
  declare previousSecretExpiresAt: Date | null;
  declare createdBy: string | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeLoginHookModel = (sequelize: Sequelize) => {
  LoginHook.init(
    {
      trigger: { type: DataTypes.STRING(20), primaryKey: true, allowNull: false },
      url: { type: DataTypes.STRING(2048), allowNull: false },
      timeoutMs: { type: DataTypes.INTEGER, allowNull: false },
      failureMode: { type: DataTypes.STRING(10), allowNull: false },
      enabled: { type: DataTypes.BOOLEAN, allowNull: false },
      secretCiphertext: { type: DataTypes.TEXT, allowNull: false },
      secretIv: { type: DataTypes.TEXT, allowNull: false },
      secretTag: { type: DataTypes.TEXT, allowNull: false },
      previousSecretCiphertext: { type: DataTypes.TEXT, allowNull: true },
      previousSecretIv: { type: DataTypes.TEXT, allowNull: true },
      previousSecretTag: { type: DataTypes.TEXT, allowNull: true },
      previousSecretExpiresAt: { type: DataTypes.DATE, allowNull: true },
      createdBy: { type: DataTypes.UUID, allowNull: true },
    },
    {
      sequelize,
      tableName: 'login_hooks',
      modelName: 'LoginHook',
    },
  );
  return LoginHook;
};

export default initializeLoginHookModel;
