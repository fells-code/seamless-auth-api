/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

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
  public id!: string;
  public user_id?: string | null;
  public type!: string;
  public ip_address?: string | null;
  public user_agent?: string | null;
  public metadata!: Record<string, any> | null;
  public readonly created_at!: Date;
  public readonly updated_at!: Date;

  static associate(models: any) {
    AuthEvent.belongsTo(models.User, {
      foreignKey: 'user_id',
    });
  }
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
    },
  );

  return AuthEvent;
};

export default initializeAuthEventModel;
