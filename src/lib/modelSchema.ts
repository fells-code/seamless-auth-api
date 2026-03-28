/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
import { ModelStatic } from 'sequelize';
import { z } from 'zod';

export function zodFromModel(model: ModelStatic<any>) {
  const attributes = model.getAttributes();

  const shape: Record<string, z.ZodTypeAny> = {};

  for (const key of Object.keys(attributes)) {
    const attr = attributes[key];
    const typeKey = (attr as any)?.type?.key;

    switch (typeKey) {
      case 'STRING':
      case 'TEXT':
      case 'UUID':
        shape[key] = z.string();
        break;

      case 'INTEGER':
      case 'BIGINT':
        shape[key] = z.number();
        break;

      case 'BOOLEAN':
        shape[key] = z.boolean();
        break;

      case 'DATE':
        shape[key] = z.string();
        break;

      case 'JSON':
      case 'JSONB':
        shape[key] = z.unknown();
        break;

      default:
        shape[key] = z.unknown();
    }
  }

  return z.object(shape);
}
