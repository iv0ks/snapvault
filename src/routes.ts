// HTTP routes.
//
// The intentional vulnerability lives in `PATCH /api/snapshots/:handle`: it
// decodes the base64url handle to a snapshot id and updates that snapshot
// WITHOUT checking that it belongs to the logged-in user. That missing
// ownership check — behind a handle that merely *looks* unguessable — is the
// whole lab (write IDOR / broken access control, CWE-639).
import { Router, type Request, type Response, type NextFunction } from 'express';
import { eq, and, ne } from 'drizzle-orm';
import { db } from './db/client.js';
import { users, snapshots } from './db/schema.js';
import { verifyPassword } from './auth.js';
import { encodeHandle, decodeHandle } from './handle.js';

export const router = Router();

// ---------------------------------------------------------------------------
// Auth guard: most of the app requires a logged-in session.
// ---------------------------------------------------------------------------
function requireLogin(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.userId) {
    res.status(401).json({ error: 'Not authenticated. POST /api/login first.' });
    return;
  }
  next();
}

// ---------------------------------------------------------------------------
// Health check (used by the Docker HEALTHCHECK). Returns the literal "ok".
// ---------------------------------------------------------------------------
router.get('/healthz', (_req, res) => {
  res.type('text/plain').send('ok');
});

// ---------------------------------------------------------------------------
// Session: log in / log out.
// ---------------------------------------------------------------------------
router.post('/api/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    res.status(400).json({ error: 'username and password are required' });
    return;
  }

  const [user] = await db.select().from(users).where(eq(users.username, username)).limit(1);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({
    ok: true,
    user: { id: user.id, username: user.username, displayName: user.displayName },
  });
});

router.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// Who am I? Convenience endpoint for the UI.
router.get('/api/me', requireLogin, async (req, res) => {
  const [user] = await db
    .select({ id: users.id, username: users.username, displayName: users.displayName })
    .from(users)
    .where(eq(users.id, req.session.userId!))
    .limit(1);
  res.json({ user });
});

// ---------------------------------------------------------------------------
// Snapshot listing — the SAFE endpoint.
//
// Scopes the query to the session user, so the dashboard only ever shows your
// own snapshots. Each one is returned with its public base64url handle (never
// the raw id). A legitimate user never sees anyone else's snapshot here.
// ---------------------------------------------------------------------------
router.get('/api/snapshots', requireLogin, async (req, res) => {
  const me = req.session.userId!;
  const rows = await db
    .select({
      id: snapshots.id,
      title: snapshots.title,
      body: snapshots.body,
      visibility: snapshots.visibility,
      sharedWith: snapshots.sharedWith,
    })
    .from(snapshots)
    .where(eq(snapshots.ownerId, me));

  res.json({
    snapshots: rows.map((r) => ({
      handle: encodeHandle(r.id),
      title: r.title,
      body: r.body,
      visibility: r.visibility,
      sharedWith: r.sharedWith,
    })),
  });
});

// ---------------------------------------------------------------------------
// Activity feed — the ENABLER.
//
// A public-to-logged-in feed of recent *shared* snapshots across the workspace,
// meant to help teammates discover shared captures. It leaks the base64url
// handle of other users' snapshots (e.g. one of bob's). On its own that is
// "just" information disclosure — but combined with the write IDOR below it is
// the breadcrumb that reveals the handle format and the neighbouring ids, so
// the attacker does not have to blind-guess.
// ---------------------------------------------------------------------------
router.get('/api/activity', requireLogin, async (req, res) => {
  const me = req.session.userId!;
  const rows = await db
    .select({
      id: snapshots.id,
      title: snapshots.title,
      ownerName: users.displayName,
    })
    .from(snapshots)
    .innerJoin(users, eq(snapshots.ownerId, users.id))
    .where(and(eq(snapshots.visibility, 'shared'), ne(snapshots.ownerId, me)));

  res.json({
    activity: rows.map((r) => ({
      handle: encodeHandle(r.id),
      title: r.title,
      owner: r.ownerName,
    })),
  });
});

// ---------------------------------------------------------------------------
// Snapshot detail — a read that DOES enforce access.
//
// You may read a snapshot if you own it OR it is shared with your username.
// This check is correct on purpose: the lab's flaw is on the *write* path, and
// this read is what lets the attacker observe the result of the write (once the
// victim's snapshot is shared to them, this returns it — flag included).
// ---------------------------------------------------------------------------
router.get('/api/snapshots/:handle', requireLogin, async (req, res) => {
  const id = decodeHandle(req.params.handle);
  if (id === null) {
    res.status(400).json({ error: 'invalid snapshot handle' });
    return;
  }

  const [snap] = await db.select().from(snapshots).where(eq(snapshots.id, id)).limit(1);
  if (!snap) {
    res.status(404).json({ error: 'snapshot not found' });
    return;
  }

  const [me] = await db
    .select({ username: users.username })
    .from(users)
    .where(eq(users.id, req.session.userId!))
    .limit(1);

  const isOwner = snap.ownerId === req.session.userId;
  const isSharedWithMe = snap.sharedWith !== '' && snap.sharedWith === me?.username;
  if (!isOwner && !isSharedWithMe) {
    res.status(403).json({ error: 'you do not have access to this snapshot' });
    return;
  }

  res.json({ snapshot: { handle: encodeHandle(snap.id), ...snap } });
});

// ---------------------------------------------------------------------------
// Snapshot update — the VULNERABLE endpoint (write IDOR / CWE-639).
//
// It requires you to be logged in, decodes the handle to an id, and updates
// the snapshot's editable fields. What it NEVER does is verify that
// `snapshot.ownerId` matches the session user. Any authenticated user can
// modify ANY snapshot by decoding its handle, changing the embedded id, and
// re-encoding — including the victim's private snapshot that carries the flag.
//
// The exploit pivot: PATCH the victim's snapshot setting `sharedWith` to your
// own username, then read it back via GET above.
//
// The fix (see SOLUTION.md) is a single added guard before writing:
//   if (snap.ownerId !== req.session.userId) return res.status(403)...
// ---------------------------------------------------------------------------
router.patch('/api/snapshots/:handle', requireLogin, async (req, res) => {
  const id = decodeHandle(req.params.handle);
  if (id === null) {
    res.status(400).json({ error: 'invalid snapshot handle' });
    return;
  }

  const [snap] = await db.select().from(snapshots).where(eq(snapshots.id, id)).limit(1);
  if (!snap) {
    res.status(404).json({ error: 'snapshot not found' });
    return;
  }

  // ⚠️ MISSING OWNERSHIP CHECK — this is the intentional vulnerability.
  // A correct implementation would reject snapshots not owned by the
  // authenticated user before applying any update.

  const { title, body, visibility, sharedWith } = req.body ?? {};
  const update: Partial<typeof snapshots.$inferInsert> = {};
  if (typeof title === 'string') update.title = title;
  if (typeof body === 'string') update.body = body;
  if (visibility === 'private' || visibility === 'shared') update.visibility = visibility;
  if (typeof sharedWith === 'string') update.sharedWith = sharedWith;

  if (Object.keys(update).length === 0) {
    res.status(400).json({ error: 'no editable fields provided' });
    return;
  }

  const [updated] = await db.update(snapshots).set(update).where(eq(snapshots.id, id)).returning();

  res.json({ ok: true, snapshot: { handle: encodeHandle(updated!.id), ...updated } });
});
