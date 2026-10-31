/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export type OidcClientType = 'public' | 'confidential';

export type OidcClientAuthMethod =
  'private_key_jwt' | 'none' | 'client_secret_basic' | 'client_secret_post';

export interface OidcClientAttributes {
  id: string;
  name: string;
  firstParty: boolean;
  clientType: OidcClientType;
  tokenEndpointAuthMethod: OidcClientAuthMethod;
  jwks?: { keys: Record<string, unknown>[] } | null;
  jwksUri?: string | null;
  /** HMAC of an opted-in shared secret, as refresh tokens are stored. Never the secret. */
  secretLookup?: string | null;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  grantTypes: string[];
  backchannelLogoutUri?: string | null;
  accessTokenTtlSeconds?: number | null;
  idTokenTtlSeconds?: number | null;
  refreshTokenTtlSeconds?: number | null;
  deviceFlowEnabled: boolean;
  noticesEnabled: boolean;
  pkceRequired: boolean;
  nonceRequired: boolean;
  disabledAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type OidcClientCreationAttributes = Optional<
  OidcClientAttributes,
  | 'firstParty'
  | 'jwks'
  | 'jwksUri'
  | 'secretLookup'
  | 'redirectUris'
  | 'postLogoutRedirectUris'
  | 'grantTypes'
  | 'backchannelLogoutUri'
  | 'accessTokenTtlSeconds'
  | 'idTokenTtlSeconds'
  | 'refreshTokenTtlSeconds'
  | 'deviceFlowEnabled'
  | 'noticesEnabled'
  | 'pkceRequired'
  | 'nonceRequired'
  | 'disabledAt'
>;

export class OidcClient
  extends Model<OidcClientAttributes, OidcClientCreationAttributes>
  implements OidcClientAttributes
{
  declare id: string;
  declare name: string;
  declare firstParty: boolean;
  declare clientType: OidcClientType;
  declare tokenEndpointAuthMethod: OidcClientAuthMethod;
  declare jwks: { keys: Record<string, unknown>[] } | null;
  declare jwksUri: string | null;
  declare secretLookup: string | null;
  declare redirectUris: string[];
  declare postLogoutRedirectUris: string[];
  declare grantTypes: string[];
  declare backchannelLogoutUri: string | null;
  declare accessTokenTtlSeconds: number | null;
  declare idTokenTtlSeconds: number | null;
  declare refreshTokenTtlSeconds: number | null;
  declare deviceFlowEnabled: boolean;
  declare noticesEnabled: boolean;
  declare pkceRequired: boolean;
  declare nonceRequired: boolean;
  declare disabledAt: Date | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeOidcClientModel = (sequelize: Sequelize) => {
  OidcClient.init(
    {
      id: { type: DataTypes.STRING(255), primaryKey: true },
      name: { type: DataTypes.STRING(255), allowNull: false },
      firstParty: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
      clientType: { type: DataTypes.STRING(16), allowNull: false },
      tokenEndpointAuthMethod: { type: DataTypes.STRING(32), allowNull: false },
      jwks: { type: DataTypes.JSONB, allowNull: true },
      jwksUri: { type: DataTypes.TEXT, allowNull: true },
      secretLookup: { type: DataTypes.STRING(64), allowNull: true },
      redirectUris: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
      postLogoutRedirectUris: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
      grantTypes: {
        type: DataTypes.JSONB,
        allowNull: false,
        defaultValue: ['authorization_code', 'refresh_token'],
      },
      backchannelLogoutUri: { type: DataTypes.TEXT, allowNull: true },
      accessTokenTtlSeconds: { type: DataTypes.INTEGER, allowNull: true },
      idTokenTtlSeconds: { type: DataTypes.INTEGER, allowNull: true },
      refreshTokenTtlSeconds: { type: DataTypes.INTEGER, allowNull: true },
      deviceFlowEnabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
      noticesEnabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
      pkceRequired: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
      nonceRequired: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
      disabledAt: { type: DataTypes.DATE, allowNull: true },
    },
    {
      sequelize,
      tableName: 'oidc_clients',
      modelName: 'OidcClient',
    },
  );
  return OidcClient;
};

export default initializeOidcClientModel;
