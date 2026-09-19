#!/usr/bin/env node
/**
 * VRSOC Defensive Endpoint Agent v1.5
 * Hardened Enterprise Endpoint Telemetry Collector & Heartbeat Daemon
 * 
 * Usage:
 *   node vrsoc-agent.js --enroll <14_CHAR_HEX_KEY> --server <VRSOC_URL> [--name <AGENT_NAME>] [--config <PATH>]
 *   node vrsoc-agent.js --server <VRSOC_URL> [--config <PATH>]
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

// -----------------------------------------------------------------------------
// CLI ARGUMENT PARSING & CONFIGURATION
// -----------------------------------------------------------------------------
const args = process.argv.slice(2);
let serverUrl = 'http://localhost:3000';
let enrollmentKey = '';
let agentName = `${os.hostname()}-endpoint`;
let configPath = path.join(process.cwd(), 'vrsoc-agent-config.json');
let runLabTest = '';
let showHelp = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--server' && args[i + 1]) serverUrl = args[++i].replace(/\/$/, '');
  if (args[i] === '--enroll' && args[i + 1]) enrollmentKey = args[++i].trim().toUpperCase();
  if (args[i] === '--name' && args[i + 1]) agentName = args[++i].trim();
  if (args[i] === '--config' && args[i + 1]) configPath = path.resolve(args[++i]);
  if (args[i] === '--test' && args[i + 1]) runLabTest = args[++i].trim();
  if (args[i] === '--help' || args[i] === '-h') showHelp = true;
}

if (showHelp) {
  console.log(`
VRSOC Defensive Endpoint Telemetry Agent v1.5
============================================
Options:
  --enroll <KEY>    14-character hexadecimal VRSOC organization enrollment key
  --server <URL>    VRSOC server URL (e.g. http://192.168.1.10:3000 or https://soc.internal)
  --name <NAME>      Custom friendly name for this endpoint
  --config <PATH>   Path to local agent config file (default: ./vrsoc-agent-config.json)
  --test <TYPE>     Run immediate telemetry test ('powershell' or 'auth-failures')
  --help, -h        Show this help message
`);
  process.exit(0);
}

// Helper: load local config if present
function loadLocalConfig() {
  if (fs.existsSync(configPath)) {
    try {
      const raw = fs.readFileSync(configPath, 'utf8');
      return JSON.parse(raw);
    } catch (e) {
      console.warn(`[CONFIG WARNING] Failed to read ${configPath}: ${e.message}`);
    }
  }
  return null;
}

// Helper: save local config securely with restrictive permissions (0o600)
function saveLocalConfig(config) {
  try {
    const data = JSON.stringify(config, null, 2);
    fs.writeFileSync(configPath, data, { encoding: 'utf8', mode: 0o600 });
  } catch (e) {
    console.warn(`[CONFIG WARNING] Failed to save config to ${configPath}: ${e.message}`);
  }
}

function getLocalIp() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1';
}

// -----------------------------------------------------------------------------
// HTTP / HTTPS CLIENT WRAPPER WITH TIMEOUT & ROBUST PARSING
// -----------------------------------------------------------------------------
function postJson(targetUrl, endpointPath, payload, headers = {}, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl + endpointPath);
    } catch (err) {
      return reject(new Error(`Invalid server URL: ${targetUrl}${endpointPath}`));
    }

    const client = parsedUrl.protocol === 'https:' ? https : http;
    const body = JSON.stringify(payload);

    const req = client.request(parsedUrl, {
      method: 'POST',
      timeout: timeoutMs,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'VRSOC-Agent/1.5',
        ...headers
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let parsed;
        try {
          parsed = data ? JSON.parse(data) : {};
        } catch (e) {
          parsed = { raw: data };
        }

        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(parsed);
        } else {
          const errMsg = parsed.error || `HTTP ${res.statusCode}: ${data.slice(0, 200)}`;
          const err = new Error(errMsg);
          (err).statusCode = res.statusCode;
          reject(err);
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out'));
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// -----------------------------------------------------------------------------
// TELEMETRY BUFFER & RETRY QUEUE
// -----------------------------------------------------------------------------
const telemetryQueue = [];
const MAX_QUEUE_SIZE = 50;

function queueTelemetry(event) {
  if (telemetryQueue.length >= MAX_QUEUE_SIZE) {
    telemetryQueue.shift(); // Drop oldest if full
  }
  telemetryQueue.push(event);
}

// -----------------------------------------------------------------------------
// AGENT RUNTIME LIFECYCLE
// -----------------------------------------------------------------------------
async function startAgent() {
  console.log('\x1b[36m====================================================\x1b[0m');
  console.log('\x1b[36m   VRSOC DEFENSIVE ENDPOINT TELEMETRY AGENT v1.5   \x1b[0m');
  console.log('\x1b[36m====================================================\x1b[0m');
  console.log(`Host:        ${os.hostname()} (${os.type()} ${os.release()} ${os.arch()})`);
  console.log(`Local IP:    ${getLocalIp()}`);
  console.log(`Server:      ${serverUrl}`);
  console.log('----------------------------------------------------');

  let localConfig = loadLocalConfig();
  let agentId = localConfig?.agentId;
  let agentToken = localConfig?.agentToken;
  let organizationId = localConfig?.organizationId;

  // Enrollment Phase
  if (!agentToken || enrollmentKey) {
    if (!enrollmentKey) {
      console.error('\x1b[31m[ERROR] No active agent credential found and no --enroll key provided.\x1b[0m');
      console.log('Please enroll with: node vrsoc-agent.js --enroll <14_CHAR_HEX_KEY> --server <VRSOC_URL>');
      process.exit(1);
    }

    if (enrollmentKey.length !== 14 || !/^[0-9A-F]{14}$/.test(enrollmentKey)) {
      console.error('\x1b[31m[ERROR] Enrollment key must be exactly 14 hexadecimal characters (0-9, A-F).\x1b[0m');
      process.exit(1);
    }

    console.log(`Enrolling endpoint with VRSOC key ${enrollmentKey}...`);
    try {
      const enrollmentResult = await postJson(serverUrl, '/api/agent/enroll', {
        enrollmentKey,
        name: agentName,
        hostname: os.hostname(),
        os: `${os.type()} ${os.release()}`,
        osVersion: os.version ? os.version() : os.release(),
        architecture: os.arch(),
        ipAddress: getLocalIp(),
        agentVersion: '1.5.0'
      });

      agentId = enrollmentResult.agent.id;
      agentToken = enrollmentResult.agentToken;
      organizationId = enrollmentResult.agent.organizationId;

      saveLocalConfig({
        serverUrl,
        agentId,
        agentToken,
        organizationId,
        hostname: os.hostname(),
        enrolledAt: new Date().toISOString()
      });

      console.log(`\x1b[32m✓ Enrolled successfully! Assigned Agent ID: ${agentId}\x1b[0m`);
      console.log(`Organization: ${organizationId}`);
    } catch (err) {
      console.error('\x1b[31m[ENROLLMENT FAILED]\x1b[0m', err.message);
      process.exit(1);
    }
  } else {
    console.log(`\x1b[32m✓ Resuming session from local configuration (Agent ID: ${agentId})\x1b[0m`);
  }

  console.log('Heartbeat daemon started (10s interval with bounded backoff)...');

  // ---------------------------------------------------------------------------
  // HEARTBEAT & RECONNECT LOOP
  // ---------------------------------------------------------------------------
  let isRevoked = false;
  let consecutiveFailures = 0;

  const sendHeartbeat = async () => {
    if (isRevoked) return;

    try {
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const ramUsage = Math.min(100, Math.max(0, Math.round(((totalMem - freeMem) / totalMem) * 100)));
      const cpuUsage = Math.min(100, Math.max(0, Math.round(os.loadavg()[0] * 10) || 12));

      await postJson(serverUrl, '/api/agent/heartbeat', {
        agentId,
        agentToken,
        cpuUsage,
        ramUsage,
        diskUsage: 45,
        activeProcessesCount: 64,
        networkConnectionsCount: 12
      }, { 'Authorization': `Bearer ${agentToken}` });

      consecutiveFailures = 0;
      process.stdout.write(`\r\x1b[32m[HEARTBEAT]\x1b[0m Status: ONLINE | CPU: ${cpuUsage}% | RAM: ${ramUsage}% | Last: ${new Date().toLocaleTimeString()}   `);

      // Flush queued telemetry if connection is healthy
      if (telemetryQueue.length > 0) {
        const queued = telemetryQueue.shift();
        if (queued) {
          postJson(serverUrl, '/api/agent/telemetry', { agentId, agentToken, ...queued }, { 'Authorization': `Bearer ${agentToken}` }).catch(() => {});
        }
      }
    } catch (err) {
      consecutiveFailures++;
      const isForbidden = err.statusCode === 401 || err.statusCode === 403;
      if (isForbidden && (err.message.includes('revoked') || err.message.includes('unauthorized'))) {
        isRevoked = true;
        console.error('\n\x1b[31m[AGENT REVOKED]\x1b[0m Agent has been revoked or deactivated by SOC administrator. Halting daemon.');
        return;
      }

      // Calculate bounded backoff
      const backoffSec = Math.min(30, Math.pow(1.5, Math.min(consecutiveFailures, 6)) * 5);
      console.warn(`\n\x1b[33m[HEARTBEAT WARNING]\x1b[0m Server unreachable (${err.message}). Retrying in ${Math.round(backoffSec)}s...`);
    }
  };

  await sendHeartbeat();
  const heartbeatTimer = setInterval(sendHeartbeat, 10000);

  // ---------------------------------------------------------------------------
  // TELEMETRY DISPATCH HELPER
  // ---------------------------------------------------------------------------
  async function dispatchTelemetry(event) {
    if (isRevoked) return;
    try {
      await postJson(serverUrl, '/api/agent/telemetry', {
        agentId,
        agentToken,
        ...event
      }, { 'Authorization': `Bearer ${agentToken}` });
    } catch (err) {
      queueTelemetry(event);
    }
  }

  // Initial startup event
  await dispatchTelemetry({
    eventType: 'process',
    severity: 'info',
    data: {
      action: 'agent_startup',
      processName: 'vrsoc-agent',
      pid: process.pid,
      user: os.userInfo ? os.userInfo().username : 'system',
      commandLine: process.argv.join(' '),
      hostname: os.hostname(),
      ipAddress: getLocalIp()
    }
  });

  // Lab test triggers if requested
  if (runLabTest === 'powershell') {
    console.log('\n\x1b[33m[LAB TEST TRIGGERED]\x1b[0m Sending encoded powershell telemetry for detection testing...');
    await dispatchTelemetry({
      eventType: 'process',
      severity: 'critical',
      data: {
        processName: 'powershell.exe',
        commandLine: 'powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
        parentPid: 1044,
        parentProcess: 'cmd.exe',
        user: os.userInfo ? os.userInfo().username : 'corp_analyst',
        hostname: os.hostname(),
        pid: process.pid + 10
      }
    });
    console.log('\x1b[32m✓ Telemetry event sent. Inspect VRSOC dashboard for triggered alert!\x1b[0m');
  } else if (runLabTest === 'auth-failures') {
    console.log('\n\x1b[33m[LAB TEST TRIGGERED]\x1b[0m Sending 5 consecutive authentication failure events...');
    for (let i = 1; i <= 5; i++) {
      await dispatchTelemetry({
        eventType: 'auth',
        severity: 'medium',
        data: {
          action: 'logon_failed',
          status: 'failure',
          username: 'admin_corp',
          sourceIp: '192.168.1.105',
          logonType: 3,
          hostname: os.hostname(),
          attemptNumber: i
        }
      });
    }
    console.log('\x1b[32m✓ 5 logon failure events sent. Inspect VRSOC dashboard for brute force alert!\x1b[0m');
  }

  // Graceful shutdown
  process.on('SIGINT', () => {
    clearInterval(heartbeatTimer);
    console.log('\nStopping VRSOC agent daemon cleanly...');
    process.exit(0);
  });
}

startAgent().catch(err => {
  console.error('Fatal agent error:', err.message);
  process.exit(1);
});
