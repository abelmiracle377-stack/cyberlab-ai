import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateUsername, normalizeUsername, validateBio, validateMessageBody,
  mediaKindForMime, extensionForMime, validateMedia, mediaStoragePath,
  canTransitionFriendship, conversationKey,
} from "../lib/social";

test("username normalization and validation", () => {
  assert.equal(normalizeUsername("  NeoTrace "), "neotrace");
  assert.equal(validateUsername("Neo_Trace99").ok, true);
  const bad = validateUsername("ab");
  assert.equal(bad.ok, false);
  assert.equal(validateUsername("has space").ok, false);
  assert.equal(validateUsername("WAYTOOLONG_usernameoverlimit").ok, false);
  const good = validateUsername("agent_007");
  assert.equal(good.ok && good.value, "agent_007");
});

test("bio and message length bounds", () => {
  assert.equal(validateBio("x".repeat(280)).ok, true);
  assert.equal(validateBio("x".repeat(281)).ok, false);
  assert.equal(validateMessageBody("  hello  ").ok, true);
  const trimmed = validateMessageBody("  hi  ");
  assert.equal(trimmed.ok && trimmed.value, "hi");
  assert.equal(validateMessageBody("x".repeat(4001)).ok, false);
});

test("media kind, extension and size validation", () => {
  assert.equal(mediaKindForMime("image/png"), "image");
  assert.equal(mediaKindForMime("audio/webm;codecs=opus"), "voice");
  assert.equal(mediaKindForMime("application/zip"), null);
  assert.equal(extensionForMime("image/jpeg"), "jpg");
  assert.equal(extensionForMime("audio/mpeg"), "mp3");

  const okImg = validateMedia("image/png", 1024);
  assert.equal(okImg.ok, true);
  assert.equal(okImg.ok && okImg.value.kind, "image");
  assert.equal(validateMedia("image/png", 11 * 1024 * 1024).ok, false); // over image cap
  assert.equal(validateMedia("audio/webm", 26 * 1024 * 1024).ok, false); // over voice cap
  assert.equal(validateMedia("text/plain", 10).ok, false);
  assert.equal(validateMedia("image/png", 0).ok, false);
});

test("media storage path is uid-prefixed and sanitized", () => {
  const uid = "123e4567-e89b-12d3-a456-426614174000";
  const path = mediaStoragePath(uid, "png", "abc123def456");
  assert.equal(path, `${uid}/abc123def456.png`);
  assert.throws(() => mediaStoragePath("not-a-uuid", "png", "abc123def456"));
  // Unsafe extension/id fall back to safe defaults.
  assert.equal(mediaStoragePath(uid, "../evil", "x").endsWith("/file.bin"), true);
});

test("friendship transitions", () => {
  assert.equal(canTransitionFriendship("pending", "accepted", "addressee"), true);
  assert.equal(canTransitionFriendship("pending", "declined", "addressee"), true);
  // Requester cannot accept their own request.
  assert.equal(canTransitionFriendship("pending", "accepted", "requester"), false);
  // Either side can block an accepted friendship.
  assert.equal(canTransitionFriendship("accepted", "blocked", "requester"), true);
  assert.equal(canTransitionFriendship("accepted", "accepted", "addressee"), false);
});

test("conversation key is direction-independent", () => {
  assert.equal(conversationKey("bbb", "aaa"), conversationKey("aaa", "bbb"));
  assert.equal(conversationKey("aaa", "bbb"), "aaa:bbb");
});
