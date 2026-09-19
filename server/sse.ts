import { Response } from 'express';

interface Client {
  id: string;
  orgId: string;
  res: Response;
}

const clients: Map<string, Client> = new Map();

export function registerClient(id: string, orgId: string, res: Response) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.write(`data: ${JSON.stringify({ type: 'connected', time: new Date().toISOString() })}\n\n`);

  clients.set(id, { id, orgId, res });

  // Heartbeat ping every 30s to keep SSE connection alive
  const interval = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch {
      clearInterval(interval);
      clients.delete(id);
    }
  }, 30000);

  res.on('close', () => {
    clearInterval(interval);
    clients.delete(id);
  });
}

export function broadcastEvent(orgId: string, eventType: string, payload: any) {
  const data = JSON.stringify({ type: eventType, payload, timestamp: new Date().toISOString() });
  for (const client of clients.values()) {
    if (client.orgId === orgId) {
      try {
        client.res.write(`data: ${data}\n\n`);
      } catch (err) {
        console.error('Error broadcasting to SSE client:', err);
      }
    }
  }
}
