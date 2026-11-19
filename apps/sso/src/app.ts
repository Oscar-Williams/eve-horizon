import express from 'express';
import cookieParser from 'cookie-parser';
import { contentSecurityPolicy } from './csp.js';
import { registerCallbackRoutes } from './routes/callback.js';
import { registerLandingRoutes } from './routes/landing.js';
import { registerLoginRoutes } from './routes/login.js';
import { registerSessionRoutes } from './routes/session.js';
import { registerSetPasswordRoutes } from './routes/set-password.js';
import { registerWrapRoutes } from './routes/wrap.js';

/** The SSO's Express app with every route registered (main.ts listens on it). */
export function createApp(): express.Express {
  const app = express();
  app.use(contentSecurityPolicy);
  app.use(cookieParser());
  app.use(express.json());

  registerWrapRoutes(app);
  registerLandingRoutes(app);
  registerLoginRoutes(app);
  registerCallbackRoutes(app);
  registerSetPasswordRoutes(app);
  registerSessionRoutes(app);

  return app;
}
