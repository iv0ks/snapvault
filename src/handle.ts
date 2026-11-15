// Snapshot handles.
//
// Every snapshot is addressed in the API by an opaque-looking *handle* instead
// of its raw integer id. The handle is simply the string `snap:<id>` encoded
// with base64url — e.g. snapshot 4 → `c25hcDo0`.
//
// This is the whole point of the lab: the handle *looks* unguessable, so the
// app treats it as if it were an access control. It is not. Base64 is an
// encoding, not encryption and not authorization — anyone can decode a handle,
// change the id, and re-encode it. The decode/encode helpers below are shared
// by the server (and mirror exactly what an attacker does by hand).

const PREFIX = 'snap:';

/** Encode a snapshot id into its public base64url handle. */
export function encodeHandle(id: number): string {
  return Buffer.from(`${PREFIX}${id}`, 'utf8').toString('base64url');
}

/**
 * Decode a handle back to a snapshot id. Returns null when the handle is not
 * valid base64url or does not carry a positive integer id. Note that decoding
 * only validates *shape*, never *ownership* — the vulnerable route forgets the
 * latter.
 */
export function decodeHandle(handle: unknown): number | null {
  if (typeof handle !== 'string' || handle.length === 0) return null;
  let decoded: string;
  try {
    decoded = Buffer.from(handle, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  if (!decoded.startsWith(PREFIX)) return null;
  const raw = decoded.slice(PREFIX.length);
  const id = Number(raw);
  if (!Number.isInteger(id) || id < 1) return null;
  return id;
}
