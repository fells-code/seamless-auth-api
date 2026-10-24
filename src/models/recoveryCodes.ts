/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface RecoveryCodeAttributes {
  id: string;
  userId: string;
  codeHash: string;
  usedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type RecoveryCodeCreationAttributes = Optional<RecoveryCodeAttributes, 'id' | 'usedAt'>;

export class RecoveryCode
  extends Model<RecoveryCodeAttributes, RecoveryCodeCreationAttributes>
  implements RecoveryCodeAttributes
{
  declare id: string;
  declare userId: string;
  declare codeHash: string;
  declare usedAt: Date | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeRecoveryCodeModel = (sequelize: Sequelize) => {
  RecoveryCode.init(
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
      codeHash: {
        type: DataTypes.STRING(64),
        allowNull: false,
      },
      usedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
      tableName: 'recovery_codes',
      modelName: 'RecoveryCode',
    },
  );

  return RecoveryCode;
};

export default initializeRecoveryCodeModel;
