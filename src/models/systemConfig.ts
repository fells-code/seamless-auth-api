/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface SystemConfigAttributes {
  key: string;
  value: unknown;
  updatedBy?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type SystemConfigCreationAttributes = Optional<SystemConfigAttributes, 'updatedBy'>;

export class SystemConfig
  extends Model<SystemConfigAttributes, SystemConfigCreationAttributes>
  implements SystemConfigAttributes
{
  declare key: string;
  declare value: unknown;
  declare updatedBy: string | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeSystemConfigModel = (sequelize: Sequelize) => {
  SystemConfig.init(
    {
      key: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
      },
      value: {
        type: DataTypes.JSONB,
        allowNull: false,
      },
      updatedBy: {
        type: DataTypes.UUID,
        allowNull: true,
      },
    },
    {
      sequelize,
      tableName: 'system_config',
      modelName: 'SystemConfig',
      indexes: [
        {
          unique: true,
          fields: ['key'],
        },
      ],
    },
  );

  return SystemConfig;
};

export default initializeSystemConfigModel;
