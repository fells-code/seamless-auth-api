import fs from 'fs';
import path from 'path';

import getLogger from './logger.js';

const logger = getLogger('getLocalLogs');

export async function getLocalLogs(find?: string): Promise<{
  events: {
    timestamp: number;
    message: string;
    ingestionTime: EpochTimeStamp;
  }[];
  error?: string;
}> {
  try {
    const filePath = path.resolve('./logs/app.log');

    if (!fs.existsSync(filePath)) {
      return { events: [] };
    }

    const logs = fs.readFileSync(filePath, 'utf8');

    let lines = logs.split('\n').filter(Boolean);

    // Optional search filter
    if (find) {
      const search = find.toLowerCase();
      lines = search ? lines.filter((line) => line.toLowerCase().includes(search)) : lines;
    }

    const events = lines.slice(-500).map((line) => {
      const isoMatch = line.match(/^\d{4}-\d{2}-\d{2}T[^\s]+/);
      const timestamp = isoMatch ? Date.parse(isoMatch[0]) : Date.now();

      return {
        timestamp,
        message: line,
        ingestionTime: timestamp,
      };
    });

    return { events };
  } catch (err) {
    logger.error('Error reading logs:', err);
    return { events: [], error: 'Failed to read logs' };
  }
}
