// Builds the published index.html: src/site.html encrypted behind the password gate.
// Usage: OLOA_PASSWORD='…' node build.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const password = process.env.OLOA_PASSWORD;
if (!password) {
  console.error("Set OLOA_PASSWORD, e.g. OLOA_PASSWORD='…' node build.mjs");
  process.exit(1);
}

const iterations = 250000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));

// Matches the gate's normalize(): the password is accepted in any case.
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.trim().toUpperCase()), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, readFileSync('src/site.html'));

const b64 = (b) => Buffer.from(b).toString('base64');
const payload = [b64(salt), b64(iv), b64(data), iterations].join('.');
writeFileSync('index.html', readFileSync('src/gate.html', 'utf8').replace('__PAYLOAD__', payload));
console.log('index.html written');
