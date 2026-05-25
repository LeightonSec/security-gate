// has_crypto.ts — dirty fixture for CryptoScanner: all six violation types present

import { createCipheriv } from 'crypto'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'

// CRYPTO-01: Math.random() used for session ID — not a CSPRNG
const sessionId = `${Date.now()}-${Math.random().toString(36)}`

// CRYPTO-02: createCipheriv without setAAD — GCM envelope fields unauthenticated
function encryptNoAad(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()])
  return encrypted
}

// CRYPTO-03: hkdf with undefined salt — weakens key derivation
function deriveKeyNoSalt(secret: Buffer): Buffer {
  return Buffer.from(hkdf(sha256, secret, undefined, new TextEncoder().encode('bastion-v1'), 32))
}

// CRYPTO-04: catch block silently returns null with no logging
function tryDecryptSilent(data: Buffer): Buffer | null {
  try {
    return decryptPayload(data)
  } catch {
    return null
  }
}

// CRYPTO-05: non-constant-time comparison of signature material
function verifySignature(signature: string, expected: string): boolean {
  return signature === expected
}

// CRYPTO-06: private key material passed to log function
function loadKey(privateKey: Buffer): void {
  console.log('loaded', privateKey)
}

declare function decryptPayload(data: Buffer): Buffer
