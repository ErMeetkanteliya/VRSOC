import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { logError } from './logging';

export function errorHandler(err: any, req: Request, res: Response, next: NextFunction) {
  const requestId = req.id || 'req-unknown';
  const method = req.method;
  const path = req.path;

  // 1. JSON Syntax Error (Malformed Body)
  if (err instanceof SyntaxError && 'status' in err && (err as any).status === 400 && 'body' in err) {
    logError(`Malformed JSON payload received on ${method} ${path}`, err, { requestId });
    return res.status(400).json({
      error: 'Malformed JSON payload in request body',
      requestId
    });
  }

  // 2. Zod Validation Error
  if (err instanceof ZodError) {
    const details = err.errors.map(e => ({
      field: e.path.join('.'),
      message: e.message
    }));
    logError(`Validation failure on ${method} ${path}`, err, { requestId, details });
    return res.status(400).json({
      error: details[0]?.message || 'Invalid request parameters',
      details,
      requestId
    });
  }

  // 3. PostgreSQL / Supabase Database Error Sanitization
  const isDbError = Boolean(
    err?.code && (typeof err.code === 'string' && (err.code.startsWith('23') || err.code.startsWith('42') || err.code.startsWith('PGRST'))) ||
    err?.message?.includes('violates foreign key') ||
    err?.message?.includes('duplicate key') ||
    err?.message?.includes('relation') ||
    err?.message?.includes('column') ||
    err?.message?.includes('syntax error at or near')
  );

  if (isDbError) {
    logError(`Database error on ${method} ${path}: ${err.message}`, err, { requestId, code: err.code });
    
    // Check for unique constraint violation (code 23505)
    if (err.code === '23505' || err.message?.includes('duplicate key')) {
      return res.status(409).json({
        error: 'Resource already exists or conflict occurred.',
        requestId
      });
    }

    // Generic safe DB error
    return res.status(500).json({
      error: 'Database operation failed. Please try again later.',
      requestId
    });
  }

  // 4. HTTP Status from known custom error
  const statusCode = typeof err.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 600
    ? err.statusCode
    : typeof err.status === 'number' && err.status >= 400 && err.status < 600
    ? err.status
    : 500;

  logError(`Unhandled server error on ${method} ${path}`, err, { requestId, statusCode });

  // Safe response message (ensure no stack trace or raw SQL is ever sent to client)
  let clientMessage = err.message || 'An unexpected server error occurred';
  if (statusCode === 500 && (clientMessage.includes('SELECT') || clientMessage.includes('INSERT') || clientMessage.includes('UPDATE') || clientMessage.includes('DELETE') || clientMessage.includes('supabase') || clientMessage.includes('postgres'))) {
    clientMessage = 'An internal server error occurred';
  }

  res.status(statusCode).json({
    error: clientMessage,
    requestId
  });
}
