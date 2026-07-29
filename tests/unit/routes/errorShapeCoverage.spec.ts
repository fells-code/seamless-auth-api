import express from 'express';
import { ZodObject, ZodType } from 'zod';

import { describe, expect, it } from 'vitest';

import { loadRoutes } from '../../../src/lib/loadRoutes.js';
import { registry } from '../../../src/openapi/registry.js';

/**
 * Every 4xx and 5xx response must carry a required `error` string, so a consumer can read
 * one field to learn why a call failed. Handlers used to split between `{ error }` and
 * `{ message }`, which left the shape ambiguous.
 */
describe('error response shape', () => {
  it('declares a required error string on every failure response', async () => {
    await loadRoutes(express());

    const offenders: string[] = [];
    let inspected = 0;

    for (const definition of registry.definitions) {
      if (definition.type !== 'route') continue;

      const { method, path, responses } = definition.route;

      for (const [status, response] of Object.entries(responses ?? {})) {
        if (!/^[45]/.test(status)) continue;

        const schema = (response as { content?: Record<string, { schema?: ZodType }> })?.content?.[
          'application/json'
        ]?.schema;

        if (!schema) continue;

        inspected += 1;

        const shape = schema instanceof ZodObject ? schema.shape : undefined;
        const errorField = shape?.error as ZodType | undefined;

        if (!errorField || errorField.safeParse(undefined).success) {
          offenders.push(`${method.toUpperCase()} ${path} -> ${status}`);
        }
      }
    }

    expect(offenders).toEqual([]);
    // Guards against the assertion above passing because nothing was examined.
    expect(inspected).toBeGreaterThan(100);
  });
});
