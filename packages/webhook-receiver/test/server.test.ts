/**
 * Server integration test — spins up createReceiverServer, POSTs to it,
 * asserts accept/reject/replay/health behavior end-to-end.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createHash } from 'node:crypto';
import { createReceiverServer } from '../src/server';
import type { AddressInfo } from 'node:net';

const SECRET = 'whsec_test_'.padEnd(64, 'x');
const KID = createHash('sha256').update(SECRET, 'utf8').digest('hex').slice(0, 8);

async function withServer<T>(
  config: Parameters<typeof createReceiverServer>[0],
  fn: (baseUrl: string) => Promise<T>,
): Promise<T> {
  const { server, listen, close } = createReceiverServer(config);
  await listen(0); // ephemeral port
  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  try {
    return await fn(baseUrl);
  } finally {
    await close();
  }
}

function sign(secret: string, ts: number, body: string): string {
  return createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
}

const baseLog: Record<string, unknown>[] = [];

describe('server', () => {
  it('GET /health returns 200 ok', async () => {
    await withServer(
      { secrets: [{ kid: KID, secret: SECRET }], log: () => {} },
      async (base) => {
        const r = await fetch(`${base}/health`);
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.deepEqual(j, { status: 'ok' });
      },
    );
  });

  it('POST /webhook accepts valid delivery + routes by family', async () => {
    let handled: { type: string; seq: number | null } | null = null;
    const body = JSON.stringify({
      type: 'send.created',
      id: 'evt-1',
      created_at: '2026-01-01T00:00:00Z',
      data: { chain_event_id: 'c1', sequence_number: 1, chain_hash: 'abc', previous_hash: null },
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = sign(SECRET, ts, body);
    await withServer(
      {
        secrets: [{ kid: KID, secret: SECRET }],
        handlers: { send: (e, c) => { handled = { type: e.type, seq: c.sequence_number }; } },
        log: () => {},
      },
      async (base) => {
        const r = await fetch(`${base}/webhook`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Webhook-Signature': `t=${ts},v1=${sig},kid=${KID}`,
            'X-Webhook-Event-Id': 'evt-1',
            'X-Webhook-Event-Type': 'send.created',
          },
          body,
        });
        assert.equal(r.status, 204);
      },
    );
    assert.deepEqual(handled, { type: 'send.created', seq: 1 });
  });

  it('POST /webhook returns 401 on bad signature', async () => {
    const body = JSON.stringify({ type: 'send.created', id: '1', created_at: '0', data: {} });
    const ts = Math.floor(Date.now() / 1000);
    await withServer(
      { secrets: [{ kid: KID, secret: SECRET }], log: () => {} },
      async (base) => {
        const r = await fetch(`${base}/webhook`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Webhook-Signature': `t=${ts},v1=${'00'.repeat(32)},kid=${KID}`,
          },
          body,
        });
        assert.equal(r.status, 401);
        const j = await r.json();
        assert.equal(j.error, 'no_signature_verifies');
      },
    );
  });

  it('POST /webhook returns 409 on replay (same body + timestamp)', async () => {
    const body = JSON.stringify({ type: 'send.created', id: '1', created_at: '0', data: {} });
    const ts = Math.floor(Date.now() / 1000);
    const sig = sign(SECRET, ts, body);
    await withServer(
      { secrets: [{ kid: KID, secret: SECRET }], log: () => {} },
      async (base) => {
        const r1 = await fetch(`${base}/webhook`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Webhook-Signature': `t=${ts},v1=${sig},kid=${KID}` },
          body,
        });
        assert.equal(r1.status, 204);
        const r2 = await fetch(`${base}/webhook`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Webhook-Signature': `t=${ts},v1=${sig},kid=${KID}` },
          body,
        });
        assert.equal(r2.status, 409);
        const j = await r2.json();
        assert.equal(j.error, 'replay_detected');
      },
    );
  });

  it('POST /webhook rotation-grace: dual-sig with secondary kid accepted', async () => {
    const SECRET_NEW = 'whsec_new_'.padEnd(64, 'y');
    const KID_NEW = createHash('sha256').update(SECRET_NEW, 'utf8').digest('hex').slice(0, 8);
    const body = JSON.stringify({ type: 'record.created', id: '2', created_at: '0', data: {} });
    const ts = Math.floor(Date.now() / 1000);
    const sigOld = sign(SECRET, ts, body); // primary
    const sigNew = sign(SECRET_NEW, ts, body); // secondary
    await withServer(
      { secrets: [{ kid: KID, secret: SECRET }, { kid: KID_NEW, secret: SECRET_NEW }], log: () => {} },
      async (base) => {
        const r = await fetch(`${base}/webhook`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Webhook-Signature': `t=${ts},v1=${sigOld},kid=${KID},v1=${sigNew},kid=${KID_NEW}`,
          },
          body,
        });
        assert.equal(r.status, 204);
      },
    );
  });

  it('GET /webhook returns 404', async () => {
    await withServer({ secrets: [{ kid: KID, secret: SECRET }], log: () => {} }, async (base) => {
      const r = await fetch(`${base}/webhook`);
      assert.equal(r.status, 404);
    });
  });

  void baseLog; // keep import for future log-shape tests
});
