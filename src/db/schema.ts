// Database schema (Drizzle ORM).
//
// Two tables model the whole lab:
//  - `users`     — the seeded identities (alice = you, bob = the victim).
//  - `snapshots` — a saved capture that belongs to exactly one user via
//                  `ownerId`, and can be shared with another user by username
//                  via `sharedWith`.
//
// IDs are plain sequential integers, but the API never exposes them directly:
// each snapshot is addressed by a base64url *handle* of `snap:<id>` (see
// src/handle.ts). The obfuscation is the (broken) "defence" this lab is about.
import { pgTable, serial, integer, text, timestamp } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  // The login handle (e.g. "alice"). Unique in practice; kept simple for the lab.
  username: text('username').notNull(),
  // Display name shown in the UI.
  displayName: text('display_name').notNull(),
  // This lab stores a salted SHA-256 hash (see src/auth.ts) — enough to make
  // the login realistic without native crypto deps. NEVER do this in a real app.
  passwordHash: text('password_hash').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const snapshots = pgTable('snapshots', {
  id: serial('id').primaryKey(),
  // Owner of the snapshot. THIS is the field the vulnerable PATCH forgets to
  // check against the session user.
  ownerId: integer('owner_id')
    .notNull()
    .references(() => users.id),
  // Human-facing title, e.g. "Q4 roadmap".
  title: text('title').notNull(),
  // The captured content / note body.
  body: text('body').notNull().default(''),
  // Visibility: 'private' or 'shared'.
  visibility: text('visibility').notNull().default('private'),
  // Username this snapshot is shared with ('' = nobody). Writing your own
  // username here on someone else's snapshot is the exploit's pivot: once the
  // victim's snapshot is "shared with" you, you can read it — flag included.
  sharedWith: text('shared_with').notNull().default(''),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export type User = typeof users.$inferSelect;
export type Snapshot = typeof snapshots.$inferSelect;
