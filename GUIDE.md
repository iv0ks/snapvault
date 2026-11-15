# snapvault: Learning Guide

![CWE-639](https://img.shields.io/badge/CWE--639-IDOR-red?style=flat-square)
![Node](https://img.shields.io/badge/Node-Express-000000?style=flat-square&logo=express&logoColor=white)
![Docker](https://img.shields.io/badge/Lab-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

**snapvault is an intentionally vulnerable application built for security education.** It contains a deliberate [IDOR / broken access control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
(CWE-639) flaw so you can practice finding and exploiting it in a safe and controlled environment.

<br>

> [!TIP]
> A guided, **non-spoiler** path to solving this lab. It teaches the *method*, not the answer — the exact winning request and the flag stay in [SOLUTION.md](SOLUTION.md).

<br>

## 🧬 What broken access control is

Here is the whole idea in one sentence:

> **Broken access control happens when an app checks _who you are_ but forgets
> to check _whether you're allowed to touch this particular thing_.**

Logging in answers "who are you?" — that's **authentication**. Deciding whether
*this* user may modify *this* snapshot is a separate question — that's
**authorization**. This lab is an **IDOR** (Insecure Direct Object Reference),
and specifically a **write** IDOR: the app takes an object reference from the
request and *updates* that object, never asking whether it belongs to the
caller.

The twist here is the reference itself. Earlier labs used sequential integers,
then random UUIDs. snapvault wraps the id in a **base64 handle** — the kind of
"opaque token" developers reach for *believing it hides the id*. It doesn't.
Base64 is an **encoding**, not encryption and not authorization: anyone can
decode a handle, change the number inside, and re-encode it. If the server then
acts on that id without an ownership check, the bug is exactly as alive as with
`id=1,2,3`.

Think of a cloakroom that stops using ticket numbers `1, 2, 3` and instead
writes them in a simple cipher on the stub. If the attendant hands over whatever
coat the decoded number points to — without checking it's *your* stub — the
cipher changed nothing. The check was never there.

> Want the deeper background — horizontal vs vertical escalation, why id format
> (sequential / UUID / base64 / hashids) is never the control, and the full
> workflow with **Burp Suite** and **OWASP ZAP**? Read the shared
> **[Broken Access Control field guide](https://github.com/iv0ks/appsec-labs/blob/main/docs/broken-access-control.md)**.
> This lab is a hands-on application of it.

<br>

## 🎓 What this level teaches

**Level 4 — the id is encoded, and it still doesn't matter.** The snapshot
update endpoint decodes a base64 handle to an id and writes to that snapshot
with **no check that it belongs to you**. The lesson: **an encoding is not a
secret, and it is never an access control.** Decode, alter, re-encode — the same
move an attacker makes in seconds.

- **Entry point:** `PATCH /api/snapshots/:handle`
- **The broken defence:** the handle is base64, so the app assumes it's opaque —
  being logged in is treated as enough to edit it.
- **What you can see legitimately:** your own snapshots (with their handles) via
  `GET /api/snapshots`, and a workspace activity feed via `GET /api/activity`.
- **The target:** the victim's **private** snapshot, which you can't read
  directly — but you *can* write to it.

## 🪧 How to approach it

1. Sign in as `alice` through your proxy and load the dashboard. Notice your own
   snapshots are addressed by handles like `c25hcDox`, not plain numbers.
2. **Decode a handle you own.** Run one through a base64 decoder (Burp Decoder,
   `base64 -d`, CyberArk, anything). What plaintext comes out? What structure
   does it have? Now you know the format — and how to *forge* one.
3. The activity feed hands you handles that aren't yours. Decode one of those
   too and compare. You can now see the neighbouring ids — including ones you
   were never shown.
4. You can't *read* the victim's private snapshot… but look at what the API lets
   you *do* to a snapshot by handle. If you can change a field, which field would
   turn someone else's private snapshot into one *you* are allowed to open?
5. Forge the handle for the target, send the write, then read it back.

## 🕵️‍♂️ Going further

Once you realise the update endpoint acts on *any* handle it can decode, every
snapshot is editable — you can rewrite titles, flip visibility, or re-share other
people's captures. Keep a second identity handy to prove that a snapshot owned
by B is writable while you're authenticated as A. That contrast is the proof of a
broken authorization check, independent of how "scrambled" the handle looks.

## 🤔 Why it matters

"Encode the id so users can't tamper with it" is a classic *wrong* answer to
IDOR. Base64 (or hex, or a reversible cipher) raises nothing but the attacker's
decode step. Worse, a **write** IDOR is often more damaging than a read: you're
not just seeing data you shouldn't, you're *changing* it — re-sharing, defacing,
escalating. Learning to treat any client-supplied reference as attacker-controlled,
whatever its wrapping, is the core skill this level builds.

---

When you have captured the flag (or want to check the fix and the *why* behind
it), continue to **[SOLVE → SOLUTION.md](SOLUTION.md)**.

<br>

> **Legal / ethics.** This is an educational, deliberately vulnerable lab. Run it
> only locally, on owned, isolated infrastructure, and never use these techniques
> against systems without explicit written authorization.
