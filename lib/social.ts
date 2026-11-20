// Pure, dependency-free validation helpers for the CyberLab AI social chat.
// Kept free of other imports so it compiles and unit-tests standalone (CI node --test).

export const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
export const DISPLAY_NAME_MAX = 60;
export const BIO_MAX = 280;
export const MESSAGE_MAX = 4000;
export const FRIEND_STATUSES = ["pending", "accepted", "declined", "blocked"] as const;
export type FriendStatus = (typeof FRIEND_STATUSES)[number];
export type MediaKind = "image" | "voice";

export type Validation<T> = { ok: true; value: T } | { ok: false; error: string };

export function normalizeUsername(raw: unknown): string {
  return String(raw ?? "").trim().toLowerCase();
}

export function validateUsername(raw: unknown): Validation<string> {
  const value = normalizeUsername(raw);
  if (!value) return { ok: false, error: "Choose a username." };
  if (!USERNAME_RE.test(value)) {
    return { ok: false, error: "Username must be 3–20 characters: lowercase letters, numbers or underscore." };
  }
  return { ok: true, value };
}

export function validateDisplayName(raw: unknown): Validation<string> {
  const value = String(raw ?? "").trim();
  if (value.length > DISPLAY_NAME_MAX) return { ok: false, error: `Display name must be ${DISPLAY_NAME_MAX} characters or fewer.` };
  return { ok: true, value };
}

export function validateBio(raw: unknown): Validation<string> {
  const value = String(raw ?? "").trim();
  if (value.length > BIO_MAX) return { ok: false, error: `Bio must be ${BIO_MAX} characters or fewer.` };
  return { ok: true, value };
}

export function validateMessageBody(raw: unknown): Validation<string> {
  const value = typeof raw === "string" ? raw.trim() : "";
  if (value.length > MESSAGE_MAX) return { ok: false, error: `Message must be ${MESSAGE_MAX} characters or fewer.` };
  return { ok: true, value };
}

// Allowed media MIME types, mapped to their chat kind and stored file extension.
const IMAGE_MIME: Record<string, string> = {
  "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif",
};
const VOICE_MIME: Record<string, string> = {
  "audio/webm": "webm", "audio/ogg": "ogg", "audio/mpeg": "mp3", "audio/mp4": "m4a",
  "audio/wav": "wav", "audio/x-wav": "wav", "audio/aac": "aac",
};

function baseMime(mime: string): string {
  return String(mime || "").split(";")[0].trim().toLowerCase();
}

export function mediaKindForMime(mime: unknown): MediaKind | null {
  const key = baseMime(String(mime ?? ""));
  if (key in IMAGE_MIME) return "image";
  if (key in VOICE_MIME) return "voice";
  return null;
}

export function extensionForMime(mime: unknown): string | null {
  const key = baseMime(String(mime ?? ""));
  return IMAGE_MIME[key] ?? VOICE_MIME[key] ?? null;
}

// Max media sizes (bytes): 10 MiB for images, 25 MiB for voice notes.
export const MEDIA_MAX_BYTES: Record<MediaKind, number> = { image: 10 * 1024 * 1024, voice: 25 * 1024 * 1024 };

export function validateMedia(mime: unknown, size: unknown): Validation<{ kind: MediaKind; ext: string }> {
  const kind = mediaKindForMime(mime);
  const ext = extensionForMime(mime);
  if (!kind || !ext) return { ok: false, error: "Only PNG/JPEG/WebP/GIF images or common voice recordings are allowed." };
  const bytes = typeof size === "number" ? size : NaN;
  if (!Number.isFinite(bytes) || bytes <= 0) return { ok: false, error: "Attachment is empty." };
  if (bytes > MEDIA_MAX_BYTES[kind]) {
    return { ok: false, error: `${kind === "image" ? "Image" : "Voice note"} exceeds the ${MEDIA_MAX_BYTES[kind] / (1024 * 1024)} MiB limit.` };
  }
  return { ok: true, value: { kind, ext } };
}

// A storage path for a user's upload: their uid folder + a random id + extension.
// The uid prefix is enforced by the storage RLS insert policy.
export function mediaStoragePath(uid: string, ext: string, randomId: string): string {
  if (!/^[0-9a-fA-F-]{36}$/.test(uid)) throw new Error("A valid user id is required.");
  const safeExt = /^[a-z0-9]{1,5}$/.test(ext) ? ext : "bin";
  const safeId = /^[0-9a-zA-Z_-]{8,64}$/.test(randomId) ? randomId : "file";
  return `${uid}/${safeId}.${safeExt}`;
}

// Which status changes a given party may make to a friendship.
export function canTransitionFriendship(
  from: FriendStatus, to: FriendStatus, role: "requester" | "addressee",
): boolean {
  if (from === to) return false;
  // The addressee accepts, declines or blocks a pending request.
  if (role === "addressee" && from === "pending" && (to === "accepted" || to === "declined" || to === "blocked")) return true;
  // Either party may block an accepted friendship.
  if (from === "accepted" && to === "blocked") return true;
  return false;
}

// A stable conversation key for a pair of user ids, independent of direction.
export function conversationKey(a: string, b: string): string {
  return [a, b].sort().join(":");
}
