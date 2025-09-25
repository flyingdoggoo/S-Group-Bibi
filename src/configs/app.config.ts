import dotenv from 'dotenv';
import { cleanEnv, host, port, str, bool, num, testOnly } from 'envalid';

dotenv.config();

export const appEnv = cleanEnv(process.env, {
  NODE_ENV: str({ devDefault: testOnly('development'), choices: ['development', 'production', 'test'] }),
  HOST: host({ devDefault: testOnly('localhost') }),
  PORT: port({ devDefault: testOnly(3000) }),
  CORS_ORIGIN: str({ devDefault: testOnly('http://localhost:3000') }),

  // JWT secrets & expiry (in seconds)
  JWT_ACCESS_SECRET: str({ default: 'dev_access_secret_change_me' }),
  JWT_REFRESH_SECRET: str({ default: 'dev_refresh_secret_change_me' }),
  JWT_ACCESS_EXPIRES: num({ default: 900 }), // 15 minutes
  JWT_REFRESH_EXPIRES: num({ default: 60 * 60 * 24 * 30 }), // 30 days

  // Cookie configs
  COOKIE_DOMAIN: str({ default: '' }), // empty = current host
  COOKIE_SECURE: bool({ default: false }),
  COOKIE_SAME_SITE: str({ default: 'lax', choices: ['lax', 'strict', 'none'] }),
});
