/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface OidcPayloadAttributes {
  id: string;
  model: string;
  payload: Record<string, unknown>;
  grantId?: string | null;
  userCode?: string | null;
  uid?: string | null;
  sessionId?: string | null;
  expiresAt: Date;
  consumedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type OidcPayloadCreationAttributes = Optional<
  OidcPayloadAttributes,
  'grantId' | 'userCode' | 'uid' | 'sessionId' | 'consumedAt'
>;

export class OidcPayload
  extends Model<OidcPayloadAttributes, OidcPayloadCreationAttributes>
  implements OidcPayloadAttributes
{
  declare id: string;
  declare model: string;
  declare payload: Record<string, unknown>;
  declare grantId: string | null;
  declare userCode: string | null;
  declare uid: string | null;
  declare sessionId: string | null;
  declare expiresAt: Date;
  declare consumedAt: Date | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeOidcPayloadModel = (sequelize: Sequelize) => {
  OidcPayload.init(
    {
      id: { type: DataTypes.STRING(512), primaryKey: true },
      model: { type: DataTypes.STRING(64), primaryKey: true },
      payload: { type: DataTypes.JSONB, allowNull: false },
      grantId: { type: DataTypes.STRING(512), allowNull: true },
      userCode: { type: DataTypes.STRING(512), allowNull: true },
      uid: { type: DataTypes.STRING(512), allowNull: true },
      sessionId: { type: DataTypes.UUID, allowNull: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      consumedAt: { type: DataTypes.DATE, allowNull: true },
    },
    {
      sequelize,
      tableName: 'oidc_payloads',
      modelName: 'OidcPayload',
    },
  );
  return OidcPayload;
};

export default initializeOidcPayloadModel;
