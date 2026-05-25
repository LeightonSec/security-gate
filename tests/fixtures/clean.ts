// clean.ts — no crypto violations: correct patterns throughout

import { createCipheriv, randomBytes, timingSafeEqual } from 'crypto'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'

// Good: OS CSPRNG
const iv = randomBytes(12)

// Good: createCipheriv with setAAD immediately after
function encryptGood(sessionKey: Buffer, ivBytes: Buffer, aad: Buffer, data: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-gcm', sessionKey, ivBytes)
  cipher.setAAD(aad)
  return Buffer.concat([cipher.update(data), cipher.final()])
}

// Good: hkdf with explicit salt
function deriveKey(secret: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdf(sha256, secret, salt, new TextEncoder().encode('bastion-v1'), 32))
}

// Good: catch with error logging before discarding
function tryDecrypt(data: Buffer): Buffer | null {
  try {
    return decryptPayload(data)
  } catch (err) {
    console.error('decryption failed:', err)
    return null
  }
}

// Good: constant-time comparison for signatures
function verifySignature(provided: Buffer, expected: Buffer): boolean {
  return timingSafeEqual(provided, expected)
}

declare function decryptPayload(data: Buffer): Buffer
