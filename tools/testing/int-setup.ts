/**
 * Shared setup for the integration tier. Fails the run immediately with an
 * actionable message when the docker-compose stack is down, and pins the two
 * database roles the suites rely on (owner for fixtures, ctem_app for RLS).
 */
import { requireInfra } from '@ctem/testing';

process.env.DATABASE_URL ??= 'postgresql://ctem:ctem@localhost:5432/ctem?schema=public';
process.env.DATABASE_APP_URL ??= 'postgresql://ctem_app:ctem_app@localhost:5432/ctem?schema=public';

await requireInfra();
