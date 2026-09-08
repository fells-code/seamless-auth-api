/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import http from 'http';

// The same variable server.ts binds. Hardcoding the default meant any deployment
// that set PORT, which .env.example invites, probed a closed port and reported the
// container unhealthy while the API was serving correctly.
const PORT = process.env.PORT || 5312;

http
  .get(`http://localhost:${PORT}/health/status`, (res) => {
    if (res.statusCode === 200) process.exit(0);
    process.exit(1);
  })
  .on('error', () => process.exit(1));
