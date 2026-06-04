/**
 * Reference HTTP server wiring the verify + replay-cache + router pieces.
 *
 * Uses node:http only — zero non-stdlib runtime dependencies, mirrors the
 * @val-protocol/chain-verifier zero-dep posture so an integrator's deployment
 * surface stays minimal.
 *
 * Endpoints:
 *   GET  /health         → 200 { status: 'ok' }
 *   POST /webhook        → 204 on accept / 400/401 on rejection (per IETF
 *                          conventions for delivery webhooks)
 *
 * Structured logging: each delivery prints one JSON line to stdout, parseable
 * by ELK / Loki / Datadog ingest. Field shape documented in README.
 */
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { InMemoryReplayCache } from './replay-cache.js';
import { routeEvent } from './router.js';
import { verifyWebhook } from './verify.js';
import type { RouterHandlers, Secret, WebhookEnvelope } from './types.js';

export interface ServerConfig {
  /** Port to listen on. */
  port?: number;
  /** Receiver's secret store (primary + rotation grace). */
  secrets: Secret[];
  /** Replay tolerance in seconds. Defaults to 300. */
  timestampToleranceSeconds?: number;
  /** Family-prefixed event handlers. */
  handlers?: RouterHandlers;
  /** Override `now()` for deterministic tests. */
  now?: () => number;
  /** Override log sink for tests. */
  log?: (line: Record<string, unknown>) => void;
}

function readBody(req: IncomingMessage, limitBytes = 1_000_000): Promise<string> {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limitBytes) {
        reject(new Error('body_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function jsonLog(line: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...line }) + '\n');
}

export function createReceiverServer(config: ServerConfig) {
  const replayCache = new InMemoryReplayCache(
    config.timestampToleranceSeconds ?? 300,
    10_000,
    config.now,
  );
  const log = config.log ?? jsonLog;
  const handlers = config.handlers ?? {};

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }
      if (req.method !== 'POST' || req.url !== '/webhook') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not_found' }));
        return;
      }

      const sigHeader = (req.headers['webhook-signature'] as string) || '';
      const eventId = (req.headers['x-webhook-event-id'] as string) || '';
      const eventType = (req.headers['x-webhook-event-type'] as string) || '';
      const body = await readBody(req);

      const verifyResult = verifyWebhook({
        body,
        signatureHeader: sigHeader,
        secrets: config.secrets,
        timestampToleranceSeconds: config.timestampToleranceSeconds,
        now: config.now,
      });
      if (!verifyResult.ok) {
        log({
          level: 'warn',
          msg: 'webhook_rejected',
          reason: verifyResult.reason,
          detail: verifyResult.detail,
          event_id: eventId,
          event_type: eventType,
        });
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: verifyResult.reason }));
        return;
      }

      if (replayCache.checkAndRecord(verifyResult.timestamp, body)) {
        log({
          level: 'warn',
          msg: 'webhook_replay_rejected',
          event_id: eventId,
          event_type: eventType,
          matched_kid: verifyResult.matchedKid,
          timestamp: verifyResult.timestamp,
        });
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'replay_detected' }));
        return;
      }

      let envelope: WebhookEnvelope;
      try {
        envelope = JSON.parse(body);
      } catch {
        log({ level: 'warn', msg: 'webhook_body_not_json', event_id: eventId });
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'body_not_json' }));
        return;
      }

      const { family, routed, chain } = await routeEvent(envelope, handlers);
      log({
        level: 'info',
        msg: 'webhook_accepted',
        event_id: eventId || envelope.id,
        event_type: eventType || envelope.type,
        family,
        routed,
        matched_kid: verifyResult.matchedKid,
        timestamp: verifyResult.timestamp,
        chain_event_id: chain.chain_event_id,
        sequence_number: chain.sequence_number,
        chain_hash: chain.chain_hash ? `${chain.chain_hash.slice(0, 16)}…` : null,
        previous_hash: chain.previous_hash ? `${chain.previous_hash.slice(0, 16)}…` : null,
      });
      res.writeHead(204);
      res.end();
    } catch (err) {
      log({ level: 'error', msg: 'webhook_handler_threw', error: String(err) });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal' }));
    }
  });

  return {
    server,
    listen(port = config.port ?? 4321) {
      return new Promise<void>((resolve) => server.listen(port, () => resolve()));
    },
    close() {
      return new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

/**
 * CLI entry point. Reads config from env, starts the server, logs the
 * effective secret kids on boot so the operator can cross-check against
 * the operator's webhook-endpoint config without leaking the secret bytes.
 */
export async function main(argv: string[] = process.argv.slice(2)): Promise<void> {
  void argv;
  const port = Number(process.env.PORT ?? '4321');
  const tolerance = Number(process.env.VAL_WEBHOOK_TOLERANCE_SECONDS ?? '300');
  const secrets: Secret[] = [];
  const primarySecret = process.env.VAL_WEBHOOK_SECRET_PRIMARY;
  const primaryKid = process.env.VAL_WEBHOOK_SECRET_KID_PRIMARY;
  if (primarySecret && primaryKid) secrets.push({ kid: primaryKid, secret: primarySecret });
  const secondarySecret = process.env.VAL_WEBHOOK_SECRET_SECONDARY;
  const secondaryKid = process.env.VAL_WEBHOOK_SECRET_KID_SECONDARY;
  if (secondarySecret && secondaryKid) secrets.push({ kid: secondaryKid, secret: secondarySecret });
  if (secrets.length === 0) {
    process.stderr.write(
      'VAL_WEBHOOK_SECRET_PRIMARY + VAL_WEBHOOK_SECRET_KID_PRIMARY must be set.\n',
    );
    process.exit(2);
  }
  const { listen } = createReceiverServer({
    port,
    secrets,
    timestampToleranceSeconds: tolerance,
    // Example handlers — operators register one per family they receive. The family is the
    // prefix of `event.type` before the first dot; names below are illustrative only.
    handlers: {
      resource: (e: WebhookEnvelope, c: { sequence_number: number | null }) =>
        jsonLog({ level: 'info', msg: 'resource_handler', type: e.type, seq: c.sequence_number }),
      notification: (e: WebhookEnvelope, c: { sequence_number: number | null }) =>
        jsonLog({ level: 'info', msg: 'notification_handler', type: e.type, seq: c.sequence_number }),
      unknown: (e: WebhookEnvelope) => jsonLog({ level: 'info', msg: 'unknown_handler', type: e.type }),
    },
  });
  await listen(port);
  jsonLog({
    level: 'info',
    msg: 'webhook_receiver_listening',
    port,
    tolerance_seconds: tolerance,
    kids: secrets.map((s) => s.kid),
  });
}

if (process.argv[1] && /server\.(t|j)s$/.test(process.argv[1])) {
  main().catch((err) => {
    process.stderr.write(`fatal: ${String(err)}\n`);
    process.exit(1);
  });
}
