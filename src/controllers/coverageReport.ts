/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { CoverageReportQuerySchema } from '../schemas/coverageReport.js';
import {
  buildCoverageReport,
  coverageReportCsv,
  CoverageReportError,
} from '../services/coverageReport.js';

export async function getCoverageReport(req: Request, res: Response) {
  // Re-parsed so the defaults are typed; `defineRoute` has already validated the query.
  const query = CoverageReportQuerySchema.parse(req.query);

  try {
    const report = await buildCoverageReport(query);

    if (query.format === 'csv') {
      const filename = `authentication-coverage-${report.period.from}-to-${report.period.to}.csv`;

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      return res.send(coverageReportCsv(report));
    }

    return res.json(report);
  } catch (error) {
    if (error instanceof CoverageReportError) {
      return res.status(error.status).json({ error: error.message });
    }
    throw error;
  }
}
