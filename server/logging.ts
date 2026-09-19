// Server Logging and Redaction Utilities

const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  'token',
  'agenttoken',
  'vrsockey',
  'servicerolekey',
  'secret',
  'apikey',
  'sessiontoken',
  'otp'
]);

export function redactSensitiveData(data: any, depth = 0): any {
  if (depth > 5 || data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    // Redact JWT-like strings or bearer patterns
    if (data.startsWith('Bearer ') || data.startsWith('eyJ')) {
      return '[REDACTED_TOKEN]';
    }
    if (data.includes('sb_secret_') || data.includes('sb_publishable_')) {
      return '[REDACTED_SECRET]';
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => redactSensitiveData(item, depth + 1));
  }

  if (typeof data === 'object') {
    const sanitized: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_KEYS.has(lowerKey) || lowerKey.includes('password') || lowerKey.includes('secret') || lowerKey.includes('token') || lowerKey.includes('key')) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = redactSensitiveData(value, depth + 1);
      }
    }
    return sanitized;
  }

  return data;
}

export function logInfo(message: string, meta?: Record<string, any>) {
  const sanitizedMeta = meta ? redactSensitiveData(meta) : undefined;
  if (sanitizedMeta) {
    console.log(`[INFO] ${new Date().toISOString()} ${message}`, JSON.stringify(sanitizedMeta));
  } else {
    console.log(`[INFO] ${new Date().toISOString()} ${message}`);
  }
}

export function logWarn(message: string, meta?: Record<string, any>) {
  const sanitizedMeta = meta ? redactSensitiveData(meta) : undefined;
  if (sanitizedMeta) {
    console.warn(`[WARN] ${new Date().toISOString()} ${message}`, JSON.stringify(sanitizedMeta));
  } else {
    console.warn(`[WARN] ${new Date().toISOString()} ${message}`);
  }
}

export function logError(message: string, error?: any, meta?: Record<string, any>) {
  const sanitizedMeta = meta ? redactSensitiveData(meta) : {};
  const errorMessage = error?.message || (typeof error === 'string' ? error : 'Unknown error');
  console.error(`[ERROR] ${new Date().toISOString()} ${message} - ${errorMessage}`, JSON.stringify(sanitizedMeta));
}
