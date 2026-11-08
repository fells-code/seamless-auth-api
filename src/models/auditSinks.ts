/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { AuditSinkSettings, CalloutFailure } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface AuditSinkAttributes {
  id: string;
  name: string;
  kind: AuditSinkSettings['kind'];
  enabled: boolean;
  settings: AuditSinkSettings;
  /** The `seq` of the last event the destination accepted. A bigint, so Postgres returns a string. */
  cursorSeq: string;
  /** Failed sends in a row, for the backoff. Cleared by any success. */
  failureCount: number;
  nextAttemptAt: Date | null;
  lastDeliveredAt: Date | null;
  lastFailure: CalloutFailure | null;
  lastFailureAt: Date | null;
  createdBy: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type AuditSinkCreationAttributes = Optional<
  AuditSinkAttributes,
  | 'id'
  | 'enabled'
  | 'failureCount'
  | 'nextAttemptAt'
  | 'lastDeliveredAt'
  | 'lastFailure'
  | 'lastFailureAt'
  | 'createdBy'
  | 'createdAt'
  | 'updatedAt'
>;

export class AuditSink
  extends Model<AuditSinkAttributes, AuditSinkCreationAttributes>
  implements AuditSinkAttributes
{
  declare id: string;
  declare name: string;
  declare kind: AuditSinkSettings['kind'];
  declare enabled: boolean;
  declare settings: AuditSinkSettings;
  declare cursorSeq: string;
  declare failureCount: number;
  declare nextAttemptAt: Date | null;
  declare lastDeliveredAt: Date | null;
  declare lastFailure: CalloutFailure | null;
  declare lastFailureAt: Date | null;
  declare createdBy: string | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeAuditSinkModel = (sequelize: Sequelize) => {
  AuditSink.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      name: { type: DataTypes.STRING(100), allowNull: false },
      kind: { type: DataTypes.STRING(16), allowNull: false },
      enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
      settings: { type: DataTypes.JSONB, allowNull: false },
      cursorSeq: { type: DataTypes.BIGINT, allowNull: false },
      failureCount: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      nextAttemptAt: { type: DataTypes.DATE, allowNull: true },
      lastDeliveredAt: { type: DataTypes.DATE, allowNull: true },
      lastFailure: { type: DataTypes.STRING(32), allowNull: true },
      lastFailureAt: { type: DataTypes.DATE, allowNull: true },
      createdBy: { type: DataTypes.UUID, allowNull: true },
    },
    {
      sequelize,
      tableName: 'audit_sinks',
      modelName: 'AuditSink',
    },
  );
  return AuditSink;
};

export default initializeAuditSinkModel;
