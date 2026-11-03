/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

/** A confidential client (`clientId`) acting for a public client (`linkedClientId`). */
export interface OidcClientLinkAttributes {
  clientId: string;
  linkedClientId: string;
  /** The admin who made the link. */
  createdBy?: string | null;
  createdAt?: Date;
}

type OidcClientLinkCreationAttributes = Optional<OidcClientLinkAttributes, 'createdBy'>;

export class OidcClientLink
  extends Model<OidcClientLinkAttributes, OidcClientLinkCreationAttributes>
  implements OidcClientLinkAttributes
{
  declare clientId: string;
  declare linkedClientId: string;
  declare createdBy: string | null;
  declare readonly createdAt: Date;
}

const initializeOidcClientLinkModel = (sequelize: Sequelize) => {
  OidcClientLink.init(
    {
      clientId: { type: DataTypes.STRING(255), primaryKey: true },
      linkedClientId: { type: DataTypes.STRING(255), primaryKey: true },
      createdBy: { type: DataTypes.UUID, allowNull: true },
    },
    {
      sequelize,
      tableName: 'oidc_client_links',
      modelName: 'OidcClientLink',
      updatedAt: false,
    },
  );
  return OidcClientLink;
};

export default initializeOidcClientLinkModel;
