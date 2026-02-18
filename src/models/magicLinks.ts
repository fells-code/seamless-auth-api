/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import {
  CreationOptional,
  DataTypes,
  InferAttributes,
  InferCreationAttributes,
  Model,
  Sequelize,
} from 'sequelize';

import { User } from './users';

export class MagicLinkToken extends Model<
  InferAttributes<MagicLinkToken>,
  InferCreationAttributes<MagicLinkToken>
> {
  declare id: CreationOptional<string>;
  declare user_id: string;
  declare token_hash: string;
  declare redirect_url: string | null;
  declare ip_hash: string | null;
  declare user_agent_hash: string | null;
  declare expires_at: Date;
  declare used_at: Date | null;
  declare created_at: CreationOptional<Date>;
}

const initializeMagicTokenModel = (sequelize: Sequelize) => {
  MagicLinkToken.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
      },
      user_id: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      token_hash: {
        type: DataTypes.TEXT,
        allowNull: false,
        unique: true,
      },
      redirect_url: {
        type: DataTypes.TEXT,
        allowNull: true,
      },
      ip_hash: {
        type: DataTypes.TEXT,
        allowNull: true,
      },
      user_agent_hash: {
        type: DataTypes.TEXT,
        allowNull: true,
      },
      expires_at: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      used_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
      },
    },
    {
      sequelize,
      tableName: 'magic_link_tokens',
      timestamps: false,
    },
  );
  return MagicLinkToken;
};

MagicLinkToken.belongsTo(User, {
  foreignKey: 'user_id',
});

export default initializeMagicTokenModel;
