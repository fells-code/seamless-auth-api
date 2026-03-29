process.env.NODE_ENV = 'test';
process.env.AUTH_MODE = 'api';
process.env.APP_ORIGIN = 'http://localhost:5174';

// Default: use mock DB mode
process.env.TEST_DB = process.env.TEST_DB || 'mock';

// Only needed if postgres mode used
process.env.DB_USER ||= 'test';
process.env.DB_PASSWORD ||= 'test';
process.env.DB_HOST ||= 'localhost';
process.env.DB_PORT ||= '5432';
process.env.DB_NAME ||= 'seamless_test';
