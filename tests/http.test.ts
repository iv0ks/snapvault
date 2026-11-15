// Integration smoke tests that do not require a live database.
//
// The full write-IDOR exploit is verified end-to-end against the Docker stack
// (see SOLUTION.md). These tests pin the guarantees that do not touch Postgres:
//   1. the health endpoint responds, and
//   2. the snapshot endpoints refuse unauthenticated callers (the auth guard
//      runs before any DB access, so no connection is opened).
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { encodeHandle, decodeHandle } from '../src/handle.js';

const app = createApp();

describe('snapvault http surface', () => {
  it('serves the health check', async () => {
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.text).toBe('ok');
  });

  it('requires a session to list snapshots', async () => {
    const res = await request(app).get('/api/snapshots');
    expect(res.status).toBe(401);
  });

  it('requires a session to read a snapshot by handle', async () => {
    const res = await request(app).get(`/api/snapshots/${encodeHandle(4)}`);
    expect(res.status).toBe(401);
  });

  it('requires a session to PATCH a snapshot (the write-IDOR endpoint)', async () => {
    const res = await request(app)
      .patch(`/api/snapshots/${encodeHandle(4)}`)
      .send({ sharedWith: 'alice' });
    expect(res.status).toBe(401);
  });
});

describe('snapvault handle encoding', () => {
  it('round-trips a snapshot id through its base64url handle', () => {
    expect(encodeHandle(4)).toBe('c25hcDo0');
    expect(decodeHandle('c25hcDo0')).toBe(4);
  });

  it('rejects malformed or non-positive handles', () => {
    expect(decodeHandle('not-base64!')).toBeNull();
    expect(decodeHandle(Buffer.from('nope:1').toString('base64url'))).toBeNull();
    expect(decodeHandle(encodeHandle(0))).toBeNull();
  });
});
