// Seeds the lab's data. Idempotent: it wipes the two tables and re-inserts a
// fixed, deterministic dataset so the challenge is identical on every boot.
//
// The cast of characters IS the scenario:
//   - alice  — YOU. A low-privilege user with a couple of her own snapshots.
//   - bob    — the victim. His private snapshot (id 4) carries the flag.
//   - carol  — a third user, so bob's snapshot isn't trivially "the other one".
//
// Snapshot ids are sequential, but the API only ever shows base64url handles.
// Bob's private snapshot is id 4 → handle `c25hcDo0`. A public "activity feed"
// leaks that handle (see routes.ts), which is the breadcrumb that makes the
// write IDOR reachable without blind guessing.
import { db, sql } from './client.js';
import { users, snapshots } from './schema.js';
import { hashPassword } from '../auth.js';
import { config } from '../config.js';

async function main(): Promise<void> {
  console.log('[seed] resetting tables …');
  // TRUNCATE ... RESTART IDENTITY so ids are stable across reseeds.
  await sql`TRUNCATE TABLE snapshots RESTART IDENTITY CASCADE`;
  await sql`TRUNCATE TABLE users RESTART IDENTITY CASCADE`;

  // --- Users -------------------------------------------------------------
  const [alice, bob, carol] = await db
    .insert(users)
    .values([
      {
        username: 'alice',
        displayName: 'Alice Martins',
        passwordHash: hashPassword('password123'),
      },
      { username: 'bob', displayName: 'Bob Carrasco', passwordHash: hashPassword('hunter2') },
      { username: 'carol', displayName: 'Carol Nguyen', passwordHash: hashPassword('letmein1') },
    ])
    .returning();

  // --- Snapshots ---------------------------------------------------------
  // Insertion order fixes the ids (RESTART IDENTITY above):
  //   id 1, 2 → alice (you)      — listed on your dashboard
  //   id 3    → bob, shared note — surfaces in the activity feed (the hint)
  //   id 4    → bob, PRIVATE     — holds the flag; the target of the write IDOR
  //   id 5    → carol            — realistic noise
  await db.insert(snapshots).values([
    {
      ownerId: alice!.id,
      title: 'Welcome to Snapvault',
      body: 'Your saved captures live here. Share one with a teammate to collaborate.',
      visibility: 'private',
      sharedWith: '',
    },
    {
      ownerId: alice!.id,
      title: 'Sprint board — week 12',
      body: 'Screenshot of the sprint board before the demo.',
      visibility: 'shared',
      sharedWith: 'carol',
    },
    {
      ownerId: bob!.id,
      title: 'Team offsite photos',
      body: 'Group pictures from the offsite. Shared with the team.',
      visibility: 'shared',
      sharedWith: 'carol',
    },
    {
      ownerId: bob!.id,
      title: 'Password vault export',
      // The flag lives on the VICTIM's PRIVATE snapshot. It is reachable only
      // by breaking access control on PATCH /api/snapshots/:handle — writing
      // your own username into `sharedWith` so you can then read it.
      body: `Private backup — do not share. ${config.flag}`,
      visibility: 'private',
      sharedWith: '',
    },
    {
      ownerId: carol!.id,
      title: 'Design mocks v3',
      body: 'Latest homepage mockups.',
      visibility: 'private',
      sharedWith: '',
    },
  ]);

  console.log('[seed] done. users: alice, bob, carol. flag on bob private snapshot id 4.');
  await sql.end();
}

main().catch((err) => {
  console.error('[seed] failed:', err);
  process.exit(1);
});
