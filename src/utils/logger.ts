/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import 'dotenv/config';

import fs from 'fs';
import path from 'path';
import { createLogger, format, Logger, transports } from 'winston';

const { combine, timestamp, printf } = format;

const loggers: Record<string, Logger> = {};

const level = () => {
  const env = process.env.NODE_ENV || 'development';
  return env === 'development' ? 'debug' : 'info';
};

export default function getLogger(moduleName: string): Logger {
  if (loggers[moduleName]) return loggers[moduleName];

  const isProd = process.env.NODE_ENV === 'production';

  const logFormat = printf(({ level, message, timestamp }) => {
    return `${timestamp} [${moduleName}] ${level.toUpperCase()} - ${message}`;
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const transportsList: any[] = [];
  transportsList.push(
    new transports.Console({
      format: combine(timestamp(), logFormat),
    }),
  );

  if (!isProd) {
    // Ensure log directory exists
    const logDir = path.resolve('./logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    transportsList.push(
      new transports.File({
        filename: path.join(logDir, 'app.log'),
        format: combine(timestamp(), logFormat),
        maxsize: 10 * 1024 * 1024, // 10 MB rotate
        maxFiles: 5,
      }),
    );
  }

  const logger = createLogger({
    level: level(),
    format: combine(timestamp(), logFormat),
    transports: transportsList,
  });

  loggers[moduleName] = logger;
  return logger;
}
