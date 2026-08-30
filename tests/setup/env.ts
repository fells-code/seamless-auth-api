process.env.NODE_ENV = 'test';
// Set here rather than stubbed in mocks.ts: unstubEnvs reverts stubs before every test,
// which would drop this after the first test of each file.
process.env.APP_ORIGINS = 'http://localhost:5137';

// Default: use mock DB mode
process.env.TEST_DB = process.env.TEST_DB || 'mock';

// Only needed if postgres mode used
process.env.DB_USER ||= 'test';
process.env.DB_PASSWORD ||= 'test';
process.env.DB_HOST ||= 'localhost';
process.env.DB_PORT ||= '5432';
process.env.DB_NAME ||= 'seamless_test';
