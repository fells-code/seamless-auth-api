/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { DataTypes, Model, Sequelize } from 'sequelize';

export interface AuthActionAttributes {
  id?: string;
  endpoint: string;
  method: string;
  count: number;
  createdAt?: Date;
  updatedAt?: Date;
}

export class AuthAction extends Model<AuthActionAttributes> implements AuthActionAttributes {
  public id!: string;
  public endpoint!: string;
  public method!: string;
  public count!: number;

  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;
}

const initializeAuthActionModel = (sequelize: Sequelize) => {
  AuthAction.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      endpoint: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      method: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      count: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
    },
    {
      sequelize,
      modelName: 'AuthAction',
      tableName: 'auth_actions',
      indexes: [
        {
          unique: true,
          name: 'auth_action_unique_usage_key',
          fields: ['endpoint', 'method'],
        },
      ],
    },
  );

  return AuthAction;
};

export default initializeAuthActionModel;
