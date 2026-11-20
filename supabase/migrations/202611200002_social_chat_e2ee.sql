-- CyberLab AI social chat: end-to-end encryption support.
-- Run after 202611200001_social_chat.sql in the linked Supabase SQL Editor.

-- Each profile publishes its ECDH (P-256) public key so others can derive a
-- shared key to encrypt messages to it. The private key never leaves the device.
alter table public.profiles add column if not exists public_key text;

-- Messages may now carry ciphertext. `encrypted` marks E2EE rows; `body` holds
-- base64 ciphertext when encrypted; the IVs are needed to decrypt body/media.
alter table public.messages add column if not exists encrypted boolean not null default false;
alter table public.messages add column if not exists body_iv text;
alter table public.messages add column if not exists media_iv text;

-- Ciphertext (base64 + AES-GCM tag) is larger than the plaintext cap, so widen
-- the body length check.
alter table public.messages drop constraint if exists messages_body_check;
alter table public.messages add constraint messages_body_check check (char_length(body) <= 20000);
