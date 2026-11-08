/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { WebhookDisabledReason, WebhookEventType } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface WebhookEndpointAttributes {
  id: string;
  url: string;
  description: string | null;
  eventTypes: WebhookEventType[];
  enabled: boolean;
  disabledReason: WebhookDisabledReason | null;
  version: number;
  secretCiphertext: string;
  secretIv: string;
  secretTag: string;
  previousSecretCiphertext: string | null;
  previousSecretIv: string | null;
  previousSecretTag: string | null;
  previousSecretExpiresAt: Date | null;
  /** When the current run of failed deliveries began. Cleared by any success. */
  failingSince: Date | null;
  createdBy: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type WebhookEndpointCreationAttributes = Optional<
  WebhookEndpointAttributes,
  | 'id'
  | 'description'
  | 'enabled'
  | 'disabledReason'
  | 'version'
  | 'previousSecretCiphertext'
  | 'previousSecretIv'
  | 'previousSecretTag'
  | 'previousSecretExpiresAt'
  | 'failingSince'
  | 'createdBy'
  | 'createdAt'
  | 'updatedAt'
>;

export class WebhookEndpoint
  extends Model<WebhookEndpointAttributes, WebhookEndpointCreationAttributes>
  implements WebhookEndpointAttributes
{
  declare id: string;
  declare url: string;
  declare description: string | null;
  declare eventTypes: WebhookEventType[];
  declare enabled: boolean;
  declare disabledReason: WebhookDisabledReason | null;
  declare version: number;
  declare secretCiphertext: string;
  declare secretIv: string;
  declare secretTag: string;
  declare previousSecretCiphertext: string | null;
  declare previousSecretIv: string | null;
  declare previousSecretTag: string | null;
  declare previousSecretExpiresAt: Date | null;
  declare failingSince: Date | null;
  declare createdBy: string | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeWebhookEndpointModel = (sequelize: Sequelize) => {
  WebhookEndpoint.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      url: { type: DataTypes.STRING(2048), allowNull: false },
      description: { type: DataTypes.TEXT, allowNull: true },
      eventTypes: { type: DataTypes.ARRAY(DataTypes.STRING(64)), allowNull: false },
      enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
      disabledReason: { type: DataTypes.STRING(20), allowNull: true },
      version: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
      secretCiphertext: { type: DataTypes.TEXT, allowNull: false },
      secretIv: { type: DataTypes.TEXT, allowNull: false },
      secretTag: { type: DataTypes.TEXT, allowNull: false },
      previousSecretCiphertext: { type: DataTypes.TEXT, allowNull: true },
      previousSecretIv: { type: DataTypes.TEXT, allowNull: true },
      previousSecretTag: { type: DataTypes.TEXT, allowNull: true },
      previousSecretExpiresAt: { type: DataTypes.DATE, allowNull: true },
      failingSince: { type: DataTypes.DATE, allowNull: true },
      createdBy: { type: DataTypes.UUID, allowNull: true },
    },
    {
      sequelize,
      tableName: 'webhook_endpoints',
      modelName: 'WebhookEndpoint',
    },
  );
  return WebhookEndpoint;
};

export default initializeWebhookEndpointModel;
