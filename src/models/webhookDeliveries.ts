/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { CalloutFailure, WebhookDeliveryStatus } from '@seamless-auth/types';
import { DataTypes, Model, Optional, Sequelize } from 'sequelize';

export interface WebhookDeliveryAttributes {
  /** The `webhook-id` header and the event's `id`. */
  id: string;
  endpointId: string;
  eventType: string;
  /** The audit row the event came from. Null for a test event. */
  authEventSeq: string | null;
  /** The exact body signed and sent, so a retry or redelivery sends the same bytes. */
  payload: string;
  status: WebhookDeliveryStatus;
  attempts: number;
  nextAttemptAt: Date | null;
  lastAttemptAt: Date | null;
  lastStatusCode: number | null;
  lastFailure: CalloutFailure | null;
  createdAt?: Date;
  updatedAt?: Date;
}

type WebhookDeliveryCreationAttributes = Optional<
  WebhookDeliveryAttributes,
  | 'authEventSeq'
  | 'attempts'
  | 'nextAttemptAt'
  | 'lastAttemptAt'
  | 'lastStatusCode'
  | 'lastFailure'
  | 'createdAt'
  | 'updatedAt'
>;

export class WebhookDelivery
  extends Model<WebhookDeliveryAttributes, WebhookDeliveryCreationAttributes>
  implements WebhookDeliveryAttributes
{
  declare id: string;
  declare endpointId: string;
  declare eventType: string;
  declare authEventSeq: string | null;
  declare payload: string;
  declare status: WebhookDeliveryStatus;
  declare attempts: number;
  declare nextAttemptAt: Date | null;
  declare lastAttemptAt: Date | null;
  declare lastStatusCode: number | null;
  declare lastFailure: CalloutFailure | null;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

const initializeWebhookDeliveryModel = (sequelize: Sequelize) => {
  WebhookDelivery.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true, allowNull: false },
      endpointId: { type: DataTypes.UUID, allowNull: false },
      eventType: { type: DataTypes.STRING(64), allowNull: false },
      authEventSeq: { type: DataTypes.BIGINT, allowNull: true },
      payload: { type: DataTypes.TEXT, allowNull: false },
      status: { type: DataTypes.STRING(20), allowNull: false },
      attempts: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      nextAttemptAt: { type: DataTypes.DATE, allowNull: true },
      lastAttemptAt: { type: DataTypes.DATE, allowNull: true },
      lastStatusCode: { type: DataTypes.INTEGER, allowNull: true },
      lastFailure: { type: DataTypes.STRING(32), allowNull: true },
    },
    {
      sequelize,
      tableName: 'webhook_deliveries',
      modelName: 'WebhookDelivery',
    },
  );
  return WebhookDelivery;
};

export default initializeWebhookDeliveryModel;
