
import { healthCheckRegistry, healthCheckRouter } from './healthCheck/healthCheck.router';
import { authRegistry, authRouter } from './auth/auth.router';

export const Registries = [healthCheckRegistry, authRegistry];

export const Modules = {
  healthCheckRouter,
  authRouter,
};
