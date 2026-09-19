#!/usr/bin/env node
/**
 * VRSOC Defensive Endpoint Agent
 * Enterprise Endpoint Telemetry Collector & Heartbeat Daemon
 * 
 * Usage:
 *   node vrsoc-agent.js --enroll <14_CHAR_HEX_KEY> --server <VRSOC_URL> [--name <AGENT_NAME>]
 */

const os = require('os');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execSync } = require('child_process');

const args = process.argv.slice(2);
let serverUrl = 'http://localhost:3000';
let enrollmentKey = '';
let agentName = `${os.hostname()}-endpoint`;
let runLabTest = '';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--server' && args[i + 1]) serverUrl = args[++i].replace(/\/$/, '');
  if (args[i] === '--enroll' && args[i + 1]) enrollmentKey = args[++i].toUpperCase();
  if (args[i] === '--name' && args[i + 1]) agentName = args[++i];
  if (args[i] === '--test' && args[i + 1]) runLabTest = args[++i];
}

if (!enrollmentKey) {
  console.error('\x1b[31m[VRSOC AGENT ERROR] Missing required --enroll <14_CHAR_HEX_KEY>\x1b[0m');
  console.log('Example: node vrsoc-agent.js --enroll A7F29C81D40E5B --server http://localhost:3000');
  process.exit(1);
}

if (enrollmentKey.length !== 14 || !/^[0-9A-F]{14}$/.test(enrollmentKey)) {
  console.error('\x1b[31m[VRSOC AGENT ERROR] Enrollment key must be exactly 14 hexadecimal characters (0-9, A-F).\x1b[0m');
  console.error(`Received: ${enrollmentKey} (${enrollmentKey.length} chars)`);
  process.exit(1);
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

function postJson(path, payload, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(serverUrl + path);
    const client = url.protocol === 'https:' ? https : http;
    const body = JSON.stringify(payload);

    const req = client.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...headers
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(new Error(parsed.error || `HTTP ${res.statusCode}: ${data}`));
          }
        } catch (e) {
          reject(new Error(`Failed to parse response: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function startAgent() {
  console.log('\x1b[36m====================================================\x1b[0m');
  console.log('\x1b[36m   VRSOC DEFENSIVE ENDPOINT TELEMETRY AGENT v1.4   \x1b[0m');
  console.log('\x1b[36m====================================================\x1b[0m');
  console.log(`Host:        ${os.hostname()} (${os.type()} ${os.release()} ${os.arch()})`);
  console.log(`Local IP:    ${getLocalIp()}`);
  console.log(`Server:      ${serverUrl}`);
  console.log(`VRSOC Key:   ${enrollmentKey}`);
  console.log('----------------------------------------------------');
  console.log('Enrolling endpoint with VRSOC backend...');

  let enrollmentResult;
  try {
    enrollmentResult = await postJson('/api/agent/enroll', {
      enrollmentKey,
      name: agentName,
      hostname: os.hostname(),
      os: `${os.type()} ${os.release()}`,
      osVersion: os.version ? os.version() : os.release(),
      architecture: os.arch(),
      ipAddress: getLocalIp(),
      agentVersion: '1.4.0',
      cpuCores: os.cpus().length,
      totalMemoryBytes: os.totalmem()
    });
  } catch (err) {
    console.error('\x1b[31m[ENROLLMENT FAILED]\x1b[0m', err.message);
    process.exit(1);
  }

  const { agent, agentToken } = enrollmentResult;
  console.log(`\x1b[32m✓ Enrolled successfully! Assigned Agent ID: ${agent.id}\x1b[0m`);
  console.log(`Organization: ${agent.organizationId}`);
  console.log('Heartbeat daemon started (every 10s)...');

  // Heartbeat loop
  const sendHeartbeat = async () => {
    try {
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const ramUsage = Math.round(((totalMem - freeMem) / totalMem) * 100);

      // Estimate CPU usage
      const cpus = os.cpus();
      const cpuUsage = Math.min(99, Math.max(5, Math.round(os.loadavg()[0] * 10) || 12));

      await postJson('/api/agent/heartbeat', {
        agentId: agent.id,
        agentToken,
        cpuUsage,
        ramUsage,
        diskUsage: 45,
        activeProcessesCount: 64,
        networkConnectionsCount: 12
      });
      process.stdout.write(`\r\x1b[32m[HEARTBEAT]\x1b[0m Status: ONLINE | CPU: ${cpuUsage}% | RAM: ${ramUsage}% | Last: ${new Date().toLocaleTimeString()}   `);
    } catch (err) {
      console.error('\n\x1b[33m[HEARTBEAT WARNING]\x1b[0m Failed to send heartbeat:', err.message);
    }
  };

  await sendHeartbeat();
  setInterval(sendHeartbeat, 10000);

  // Send initial startup telemetry event
  try {
    await postJson('/api/agent/telemetry', {
      agentId: agent.id,
      agentToken,
      eventType: 'process',
      severity: 'info',
      data: {
        action: 'agent_startup',
        processName: 'vrsoc-agent',
        pid: process.pid,
        user: os.userInfo().username,
        commandLine: process.argv.join(' '),
        hostname: os.hostname(),
        ipAddress: getLocalIp()
      }
    });
  } catch (e) {
    console.error('Failed to send startup event', e);
  }

  // Handle simulated lab telemetry tests if requested by analyst
  if (runLabTest === 'powershell') {
    console.log('\n\x1b[33m[LAB TEST TRIGGERED]\x1b[0m Sending encoded powershell telemetry for detection testing...');
    await postJson('/api/agent/telemetry', {
      agentId: agent.id,
      agentToken,
      eventType: 'process',
      severity: 'critical',
      data: {
        processName: 'powershell.exe',
        commandLine: 'powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
        parentPid: 1044,
        parentProcess: 'cmd.exe',
        user: os.userInfo().username,
        hostname: os.hostname(),
        pid: process.pid + 10
      }
    });
    console.log('\x1b[32m✓ Telemetry event sent. Inspect VRSOC dashboard for triggered alert!\x1b[0m');
  } else if (runLabTest === 'auth-failures') {
    console.log('\n\x1b[33m[LAB TEST TRIGGERED]\x1b[0m Sending 5 consecutive authentication failure events...');
    for (let i = 1; i <= 5; i++) {
      await postJson('/api/agent/telemetry', {
        agentId: agent.id,
        agentToken,
        eventType: 'auth',
        severity: 'medium',
        data: {
          action: 'logon_failed',
          status: 'failure',
          username: 'admin_corp',
          sourceIp: '192.168.1.105',
          logonType: 3,
          hostname: os.hostname()
        }
      });
    }
    console.log('\x1b[32m✓ 5 logon failure events sent. Inspect VRSOC dashboard for brute force alert!\x1b[0m');
  }

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\nStopping VRSOC agent daemon...');
    process.exit(0);
  });
}

startAgent().catch(err => {
  console.error('Fatal agent error:', err);
  process.exit(1);
});
