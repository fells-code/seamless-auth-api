/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import http from 'http';

http
  .get(`http://localhost:5312/health/status`, (res) => {
    if (res.statusCode === 200) process.exit(0);
    process.exit(1);
  })
  .on('error', () => process.exit(1));
