/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function generateExample(schema: any): unknown {
  if (schema instanceof z.ZodString) return 'string';
  if (schema instanceof z.ZodNumber) return 0;
  if (schema instanceof z.ZodBoolean) return true;

  if (schema instanceof z.ZodArray) {
    const elementSchema = schema.def.type;
    return [generateExample(elementSchema)];
  }

  if (schema instanceof z.ZodObject) {
    const shape = schema.shape;
    const example: Record<string, unknown> = {};

    for (const key of Object.keys(shape)) {
      example[key] = generateExample(shape[key]);
    }

    return example;
  }

  if (schema instanceof z.ZodOptional) {
    return generateExample(schema.def.innerType);
  }

  if (schema instanceof z.ZodNullable) {
    return generateExample(schema.def.innerType);
  }

  return null;
}
