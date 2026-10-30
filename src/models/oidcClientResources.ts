/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface OidcClientResourceAttributes {
  id: string;
  clientId: string;
  resourceId: string;
  /** The subset of the resource's scopes this client may request. */
  scopes: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

type OidcClientResourceCreationAttributes = Optional<OidcClientResourceAttributes, 'id' | 'scopes'>;

export class OidcClientResource
  extends Model<OidcClientResourceAttributes, OidcClientResourceCreationAttributes>
  implements OidcClientResourceAttributes
{
  declare id: string;
  declare clientId: string;
  declare resourceId: string;
  declare scopes: string[];
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeOidcClientResourceModel = (sequelize: Sequelize) => {
  OidcClientResource.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
      clientId: { type: DataTypes.STRING(255), allowNull: false },
      resourceId: { type: DataTypes.UUID, allowNull: false },
      scopes: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
    },
    {
      sequelize,
      tableName: 'oidc_client_resources',
      modelName: 'OidcClientResource',
    },
  );
  return OidcClientResource;
};

export default initializeOidcClientResourceModel;
