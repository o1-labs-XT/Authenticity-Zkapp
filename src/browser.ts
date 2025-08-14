/**
 * Browser-safe exports for authenticity-zkapp
 * Contains cross-platform functions that work in both browsers and Node.js
 */

import { Bytes, Poseidon } from 'o1js';

// Bytes32 class for this module
class Bytes32 extends Bytes(32) {}

/**
 * Cross-platform version of hashImageOffCircuit that works in browsers and Node.js
 * Should produce identical results to the Node.js crypto version
 * @param imageData - The image data as a Uint8Array
 * @returns Promise<string> - The SHA-256 hash as hex string
 */
async function hashImageOffCircuitCrossPlatform(
  imageData: Uint8Array
): Promise<string> {
  // Use Web Crypto API which is available in modern browsers and Node.js 15.7+
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    // Ensure we have a proper ArrayBuffer (handle both ArrayBuffer and SharedArrayBuffer)
    const buffer = imageData.buffer.slice(
      imageData.byteOffset,
      imageData.byteOffset + imageData.byteLength
    ) as ArrayBuffer;
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  throw new Error('Web Crypto API not available in this environment');
}

/**
 * Cross-platform version of computeOnChainCommitment
 * @param imageData - The image data as a Uint8Array
 * @returns Promise<{sha256: string, poseidon: Field}> - The SHA-256 hash and Poseidon commitment
 */
async function computeOnChainCommitmentCrossPlatform(imageData: Uint8Array) {
  // Compute SHA-256 hash using cross-platform function
  const sha256Hash = await hashImageOffCircuitCrossPlatform(imageData);

  // Convert to Bytes32
  const bytes32 = Bytes32.fromHex(sha256Hash);

  // Compute Poseidon hash of the bytes
  return {
    sha256: sha256Hash,
    poseidon: Poseidon.hash(bytes32.toFields()),
  };
}

export {
  hashImageOffCircuitCrossPlatform,
  computeOnChainCommitmentCrossPlatform,
};