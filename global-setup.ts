import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';

/**
 * Starts either api-server/server.js (secure) or api-server/server-vulnerable.js
 * (vulnerable) depending on TARGET_SCRIPT / PORT, set by the two playwright configs.
 * Both configs share this same setup/teardown pair.
 */
const PORT        = process.env.PORT ?? '3000';
const TARGET      = process.env.TARGET_SCRIPT ?? 'server.js';
const PID_FILE    = path.join(__dirname, `.api-server-${PORT}.pid`);
const HEALTH_URL  = `http://localhost:${PORT}/api/health`;
const SERVER_JS   = path.join(__dirname, 'api-server', TARGET);

function isReachable(url: string): Promise<boolean> {
  return new Promise(resolve => {
    http.get(url, res => resolve(res.statusCode === 200))
        .on('error', () => resolve(false));
  });
}

async function waitUntilReady(maxMs = 15_000): Promise<void> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    if (await isReachable(HEALTH_URL)) return;
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error(`API server (${TARGET}) did not become ready within ${maxMs / 1000}s`);
}

export default async function globalSetup() {
  if (await isReachable(HEALTH_URL)) {
    console.log(`\n[setup] API server already running on http://localhost:${PORT}\n`);
    return; // Don't write PID — teardown won't stop a server we didn't start
  }

  console.log(`\n[setup] Starting ${TARGET} on port ${PORT}…`);
  const server: ChildProcess = spawn(process.execPath, [SERVER_JS], {
    env: {
      ...process.env,
      PORT,
      JWT_SECRET: process.env.JWT_SECRET ?? 'test-secret-key-for-security-testing',
      SESSION_SECRET: process.env.SESSION_SECRET ?? 'test-session-secret',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });

  server.stdout?.on('data', (d: Buffer) => process.stdout.write(`  [api:${PORT}] ${d}`));
  server.stderr?.on('data', (d: Buffer) => process.stderr.write(`  [api:${PORT}] ${d}`));

  server.on('error', err => { throw new Error(`Failed to start API server: ${err.message}`); });
  server.on('exit', code => {
    if (code !== null && code !== 0) {
      throw new Error(`API server exited unexpectedly with code ${code}`);
    }
  });

  fs.writeFileSync(PID_FILE, String(server.pid));

  await waitUntilReady();
  console.log(`[setup] API server (${TARGET}) ready on port ${PORT} ✓\n`);
}
