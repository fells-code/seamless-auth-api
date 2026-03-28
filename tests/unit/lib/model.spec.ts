import { describe, it, expect } from 'vitest';
import { z } from 'zod';

import { zodFromModel } from '../../../src/lib/modelSchema';

function mockModel(attrs: Record<string, any>) {
  return {
    getAttributes: () => attrs,
  } as any;
}

describe('zodFromModel', () => {
  it('maps STRING-like types to z.string()', () => {
    const model = mockModel({
      name: { type: { key: 'STRING' } },
      desc: { type: { key: 'TEXT' } },
      id: { type: { key: 'UUID' } },
    });

    const schema = zodFromModel(model);

    expect(schema.shape.name).toBeInstanceOf(z.ZodString);
    expect(schema.shape.desc).toBeInstanceOf(z.ZodString);
    expect(schema.shape.id).toBeInstanceOf(z.ZodString);
  });

  it('maps numeric types to z.number()', () => {
    const model = mockModel({
      age: { type: { key: 'INTEGER' } },
      big: { type: { key: 'BIGINT' } },
    });

    const schema = zodFromModel(model);

    expect(schema.shape.age).toBeInstanceOf(z.ZodNumber);
    expect(schema.shape.big).toBeInstanceOf(z.ZodNumber);
  });

  it('maps boolean type to z.boolean()', () => {
    const model = mockModel({
      active: { type: { key: 'BOOLEAN' } },
    });

    const schema = zodFromModel(model);

    expect(schema.shape.active).toBeInstanceOf(z.ZodBoolean);
  });

  it('maps DATE to string', () => {
    const model = mockModel({
      createdAt: { type: { key: 'DATE' } },
    });

    const schema = zodFromModel(model);

    expect(schema.shape.createdAt).toBeInstanceOf(z.ZodString);
  });

  it('maps JSON types to unknown', () => {
    const model = mockModel({
      data: { type: { key: 'JSON' } },
      data2: { type: { key: 'JSONB' } },
    });

    const schema = zodFromModel(model);

    expect(schema.shape.data).toBeInstanceOf(z.ZodUnknown);
    expect(schema.shape.data2).toBeInstanceOf(z.ZodUnknown);
  });

  it('defaults unknown types to z.unknown()', () => {
    const model = mockModel({
      weird: { type: { key: 'CUSTOM_TYPE' } },
    });

    const schema = zodFromModel(model);

    expect(schema.shape.weird).toBeInstanceOf(z.ZodUnknown);
  });

  it('handles missing type safely', () => {
    const model = mockModel({
      broken: {},
    });

    const schema = zodFromModel(model);

    expect(schema.shape.broken).toBeInstanceOf(z.ZodUnknown);
  });

  it('returns a valid zod object schema', () => {
    const model = mockModel({
      name: { type: { key: 'STRING' } },
      age: { type: { key: 'INTEGER' } },
    });

    const schema = zodFromModel(model);

    const parsed = schema.parse({
      name: 'John',
      age: 30,
    });

    expect(parsed).toEqual({
      name: 'John',
      age: 30,
    });
  });
});
