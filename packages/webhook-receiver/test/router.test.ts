import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractChainFields, familyOf, routeEvent, verifyChainLink } from '../src/router';
import type { WebhookEnvelope } from '../src/types';

const sample: WebhookEnvelope = {
  type: 'send.created',
  id: 'evt-123',
  created_at: '2026-01-01T00:00:00Z',
  data: {
    chain_event_id: 'chain-abc',
    sequence_number: 1,
    chain_hash: 'abc'.repeat(21) + 'a',
    previous_hash: null,
    send_id: 'send-xyz',
  },
};

describe('familyOf', () => {
  it('splits on first dot', () => {
    assert.equal(familyOf('send.created'), 'send');
    assert.equal(familyOf('record.appended.ai.draft.proposal'), 'record');
    assert.equal(familyOf('flat_no_dot'), 'flat_no_dot');
  });
});

describe('extractChainFields', () => {
  it('pulls all four chain fields when present', () => {
    const c = extractChainFields(sample);
    assert.equal(c.chain_event_id, 'chain-abc');
    assert.equal(c.sequence_number, 1);
    assert.equal(typeof c.chain_hash, 'string');
    assert.equal(c.previous_hash, null);
  });

  it('coerces sequence_number from string', () => {
    const e = { ...sample, data: { ...sample.data, sequence_number: '42' } };
    assert.equal(extractChainFields(e).sequence_number, 42);
  });

  it('returns nulls when fields are missing', () => {
    const e = { ...sample, data: {} };
    const c = extractChainFields(e);
    assert.equal(c.chain_event_id, null);
    assert.equal(c.sequence_number, null);
    assert.equal(c.chain_hash, null);
    assert.equal(c.previous_hash, null);
  });
});

describe('routeEvent', () => {
  it('dispatches to the correct family handler', async () => {
    const calls: string[] = [];
    const result = await routeEvent(sample, {
      send: (e) => { calls.push(`send:${e.type}`); },
      record: (e) => { calls.push(`record:${e.type}`); },
    });
    assert.deepEqual(calls, ['send:send.created']);
    assert.equal(result.family, 'send');
    assert.equal(result.routed, true);
  });

  it('falls back to `unknown` handler for un-registered families', async () => {
    const calls: string[] = [];
    const e = { ...sample, type: 'novel.frontier.event' };
    await routeEvent(e, { unknown: (ev) => { calls.push(`unknown:${ev.type}`); } });
    assert.deepEqual(calls, ['unknown:novel.frontier.event']);
  });

  it('routed=false when no handler matches and no unknown fallback', async () => {
    const e = { ...sample, type: 'mystery.event' };
    const result = await routeEvent(e, {});
    assert.equal(result.routed, false);
    assert.equal(result.family, 'mystery');
  });

  it('passes chain fields to the handler', async () => {
    let captured: any = null;
    await routeEvent(sample, { send: (_e, c) => { captured = c; } });
    assert.equal(captured.sequence_number, 1);
    assert.equal(captured.chain_event_id, 'chain-abc');
  });
});

describe('verifyChainLink', () => {
  it('returns ok on genesis (prior=null, observed=null)', () => {
    assert.deepEqual(verifyChainLink(null, { previous_hash: null }), { ok: true });
  });
  it('returns ok when previous_hash matches prior chain_hash', () => {
    const r = verifyChainLink({ chain_hash: 'aaa' }, { previous_hash: 'aaa' });
    assert.equal(r.ok, true);
  });
  it('returns fail when previous_hash mismatches', () => {
    const r = verifyChainLink({ chain_hash: 'aaa' }, { previous_hash: 'bbb' });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'previous_hash_mismatch');
  });
  it('returns fail when expecting genesis but got a hash', () => {
    const r = verifyChainLink(null, { previous_hash: 'aaa' });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'expected_genesis_link');
  });
});
