/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

import { redactMetadata } from '../utils/redaction.js';

export interface AuthEventAttributes {
  id: string;
  user_id?: string | null;
  type: string;
  ip_address?: string | null;
  user_agent?: string | null;
  metadata?: Record<string, any> | null;
  created_at?: Date;
  updated_at?: Date;
}

type AuthEventCreationAttributes = Optional<
  AuthEventAttributes,
  'id' | 'created_at' | 'updated_at'
>;

export class AuthEvent
  extends Model<AuthEventAttributes, AuthEventCreationAttributes>
  implements AuthEventAttributes
{
  declare id: string;
  declare user_id?: string | null;
  declare type: string;
  declare ip_address?: string | null;
  declare user_agent?: string | null;
  declare metadata: Record<string, any> | null;
  declare readonly created_at: Date;
  declare readonly updated_at: Date;

  static associate(models: any) {
    AuthEvent.belongsTo(models.User, {
      foreignKey: 'user_id',
    });
  }
}

function redactAuthEventMetadata(event: AuthEvent) {
  event.metadata = redactMetadata(event.metadata);
}

const initializeAuthEventModel = (sequelize: Sequelize) => {
  AuthEvent.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      user_id: {
        type: DataTypes.UUID,
        allowNull: true,
      },
      type: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      ip_address: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      user_agent: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      metadata: {
        type: DataTypes.JSONB,
        allowNull: true,
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
      },
      updated_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
      },
    },
    {
      sequelize,
      modelName: 'AuthEvent',
      tableName: 'auth_events',
      underscored: true,
      hooks: {
        beforeValidate: redactAuthEventMetadata,
        beforeCreate: redactAuthEventMetadata,
        beforeUpdate: redactAuthEventMetadata,
        beforeSave: redactAuthEventMetadata,
        beforeBulkCreate(events) {
          for (const event of events) {
            redactAuthEventMetadata(event);
          }
        },
      },
    },
  );

  return AuthEvent;
};

export default initializeAuthEventModel;
