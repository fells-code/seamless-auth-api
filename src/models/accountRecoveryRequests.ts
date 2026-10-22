/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export type RecoveryChannel = 'email' | 'phone';

/**
 * What is stored. `ready` is not one of them: a `pending` request is ready once
 * `completesAt` has passed, so nothing has to run to advance it.
 */
export type StoredRecoveryState = 'awaiting_code' | 'pending' | 'cancelled' | 'completed' | 'void';

export interface AccountRecoveryRequestAttributes {
  id: string;
  userId: string;
  channel: RecoveryChannel;
  state: StoredRecoveryState;
  attemptId?: string | null;
  codeAttemptId?: string | null;
  codeHash?: string | null;
  codeExpiresAt?: Date | null;
  failedAttempts?: number;
  cancelTokenHash?: string | null;
  requestedAt?: Date | null;
  completesAt?: Date | null;
  cancelledAt?: Date | null;
  completedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type AccountRecoveryRequestCreationAttributes = Optional<
  AccountRecoveryRequestAttributes,
  | 'id'
  | 'attemptId'
  | 'codeAttemptId'
  | 'codeHash'
  | 'codeExpiresAt'
  | 'failedAttempts'
  | 'cancelTokenHash'
  | 'requestedAt'
  | 'completesAt'
  | 'cancelledAt'
  | 'completedAt'
>;

export class AccountRecoveryRequest
  extends Model<AccountRecoveryRequestAttributes, AccountRecoveryRequestCreationAttributes>
  implements AccountRecoveryRequestAttributes
{
  declare id: string;
  declare userId: string;
  declare channel: RecoveryChannel;
  declare state: StoredRecoveryState;
  declare attemptId: string | null;
  declare codeAttemptId: string | null;
  declare codeHash: string | null;
  declare codeExpiresAt: Date | null;
  declare failedAttempts: number;
  declare cancelTokenHash: string | null;
  declare requestedAt: Date | null;
  declare completesAt: Date | null;
  declare cancelledAt: Date | null;
  declare completedAt: Date | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeAccountRecoveryRequestModel = (sequelize: Sequelize) => {
  AccountRecoveryRequest.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      channel: {
        type: DataTypes.STRING(16),
        allowNull: false,
      },
      state: {
        type: DataTypes.STRING(16),
        allowNull: false,
      },
      attemptId: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      codeAttemptId: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      codeHash: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      codeExpiresAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      failedAttempts: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      cancelTokenHash: {
        type: DataTypes.STRING(64),
        allowNull: true,
      },
      requestedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      completesAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      cancelledAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      completedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
      tableName: 'account_recovery_requests',
      modelName: 'AccountRecoveryRequest',
    },
  );

  return AccountRecoveryRequest;
};

export default initializeAccountRecoveryRequestModel;
