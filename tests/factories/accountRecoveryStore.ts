import { randomUUID } from 'crypto';
import { Op } from 'sequelize';

import { AccountRecoveryRequest } from '../../src/models/accountRecoveryRequests.js';

type Row = Record<string, any>;
type Where = Record<string | symbol, any>;

function matchesCondition(value: any, condition: any): boolean {
  if (condition === null) return value === null || value === undefined;
  if (condition instanceof Date) return value instanceof Date && +value === +condition;

  if (typeof condition === 'object') {
    return Object.getOwnPropertySymbols(condition).every((op) => {
      const operand = condition[op];
      if (op === Op.in) return operand.includes(value);
      if (op === Op.ne) return operand === null ? value != null : value !== operand;
      if (op === Op.lte) return value != null && +value <= +operand;
      throw new Error(`Unsupported operator ${String(op)}`);
    });
  }

  return value === condition;
}

function matches(row: Row, where: Where) {
  return Object.keys(where).every((key) => matchesCondition(row[key], where[key]));
}

/**
 * An in-memory stand-in for the requests table that honours the where clauses the
 * service writes, so its conditional updates are exercised rather than assumed.
 */
export function installAccountRecoveryStore() {
  const rows: Row[] = [];
  let clock = 0;

  const instance = (row: Row) => {
    Object.defineProperties(row, {
      update: { value: async (fields: Row) => Object.assign(row, fields), enumerable: false },
      reload: { value: async () => row, enumerable: false },
    });
    return row;
  };

  (AccountRecoveryRequest.create as any).mockImplementation(async (data: Row) => {
    clock += 1;
    const row = instance({
      id: randomUUID(),
      attemptId: null,
      codeAttemptId: null,
      codeHash: null,
      codeExpiresAt: null,
      failedAttempts: 0,
      cancelTokenHash: null,
      requestedAt: null,
      completesAt: null,
      cancelledAt: null,
      completedAt: null,
      createdAt: new Date(clock),
      ...data,
    });
    rows.push(row);
    return row;
  });

  (AccountRecoveryRequest.findOne as any).mockImplementation(
    async ({ where, order }: { where: Where; order?: [string, string][] }) => {
      const found = rows.filter((row) => matches(row, where));
      const key = order?.[0]?.[0];
      if (key) found.sort((a, b) => +(b[key] ?? 0) - +(a[key] ?? 0));
      return found[0] ?? null;
    },
  );

  (AccountRecoveryRequest.update as any).mockImplementation(
    async (fields: Row, { where }: { where: Where }) => {
      const found = rows.filter((row) => matches(row, where));
      for (const row of found) Object.assign(row, fields);
      return [found.length];
    },
  );

  return rows;
}
