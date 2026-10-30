/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface OidcResourceAttributes {
  id: string;
  /** An absolute URI, used as the `aud` of the resource's access tokens. */
  identifier: string;
  name: string;
  scopes: string[];
  accessTokenTtlSeconds?: number | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type OidcResourceCreationAttributes = Optional<
  OidcResourceAttributes,
  'id' | 'scopes' | 'accessTokenTtlSeconds'
>;

export class OidcResource
  extends Model<OidcResourceAttributes, OidcResourceCreationAttributes>
  implements OidcResourceAttributes
{
  declare id: string;
  declare identifier: string;
  declare name: string;
  declare scopes: string[];
  declare accessTokenTtlSeconds: number | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeOidcResourceModel = (sequelize: Sequelize) => {
  OidcResource.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
      identifier: { type: DataTypes.TEXT, allowNull: false, unique: true },
      name: { type: DataTypes.STRING(255), allowNull: false },
      scopes: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
      accessTokenTtlSeconds: { type: DataTypes.INTEGER, allowNull: true },
    },
    {
      sequelize,
      tableName: 'oidc_resources',
      modelName: 'OidcResource',
    },
  );
  return OidcResource;
};

export default initializeOidcResourceModel;
