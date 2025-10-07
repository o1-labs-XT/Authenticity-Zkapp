import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  hashImageOffCircuit,
  computeOnChainCommitment,
} from '../helpers/commitmentHelpers.js';
import {
  hashImageOffCircuitCrossPlatform,
  computeOnChainCommitmentCrossPlatform,
} from '../browser.js';
import testVectors from './testVectors.json' with { type: 'json' };

describe('Cross-Platform Parity Tests', () => {
  describe('hashImageOffCircuit parity', () => {
    testVectors.test_vectors.forEach(({ name, input_hex, sha256: expectedSha256 }: {name: string, input_hex: string, sha256: string}) => {
      it(`should match Node.js implementation for ${name}`, async () => {
        // Convert hex to Buffer/Uint8Array
        const inputBuffer = Buffer.from(input_hex, 'hex');
        const inputUint8Array = new Uint8Array(inputBuffer);
        
        // Get hash from Node.js implementation
        const nodeHash = hashImageOffCircuit(inputBuffer);
        
        // Get hash from cross-platform implementation
        const crossPlatformHash = await hashImageOffCircuitCrossPlatform(inputUint8Array);
        
        // Verify they match
        assert.strictEqual(crossPlatformHash, nodeHash);
        
        // Also verify against the expected value from test vectors
        assert.strictEqual(nodeHash, expectedSha256);
        assert.strictEqual(crossPlatformHash, expectedSha256);
      });
    });
    
    // Additional edge case tests
    it('should handle Buffer input in cross-platform version', async () => {
      const testData = Buffer.from('Test with Buffer input');
      const nodeHash = hashImageOffCircuit(testData);
      const crossPlatformHash = await hashImageOffCircuitCrossPlatform(testData);
      assert.strictEqual(crossPlatformHash, nodeHash);
    });
    
    it('should handle large data efficiently', async () => {
      const largeData = Buffer.alloc(1024 * 1024, 'x'); // 1MB of 'x'
      const nodeHash = hashImageOffCircuit(largeData);
      const crossPlatformHash = await hashImageOffCircuitCrossPlatform(new Uint8Array(largeData));
      assert.strictEqual(crossPlatformHash, nodeHash);
    });
  });

  describe('computeOnChainCommitment parity', () => {
    testVectors.test_vectors.forEach(({ name, input_hex, poseidon_commitment: expectedCommitment }: {name: string, input_hex: string, poseidon_commitment: string}) => {
      it(`should match Node.js implementation for ${name}`, async () => {
        // Convert hex to Buffer/Uint8Array
        const inputBuffer = Buffer.from(input_hex, 'hex');
        const inputUint8Array = new Uint8Array(inputBuffer);
        
        // Get commitment from Node.js implementation
        const nodeResult = await computeOnChainCommitment(inputBuffer);
        
        // Get commitment from cross-platform implementation
        const crossPlatformResult = await computeOnChainCommitmentCrossPlatform(inputUint8Array);
        
        // Verify SHA-256 hashes match
        assert.strictEqual(
          crossPlatformResult.sha256,
          nodeResult.sha256
        );
        
        // Verify high128 fields match
        assert.strictEqual(
          crossPlatformResult.high128.toBigInt().toString(),
          nodeResult.high128.toBigInt().toString()
        );
        
        // Verify low128 fields match
        assert.strictEqual(
          crossPlatformResult.low128.toBigInt().toString(),
          nodeResult.low128.toBigInt().toString()
        );
      });
    });
  });

  describe('generateECKeypair parity', () => {
    it('should produce keys with identical structure', async () => {
      const { generateECKeyPair } = await import('../helpers/commitmentHelpers.js');
      const { generateECKeypairCrossPlatform } = await import('../browser.js');
      const { Secp256r1 } = await import('../AuthenticityProof.js');

      const nodeKeys = generateECKeyPair();
      const crossPlatformKeys = await generateECKeypairCrossPlatform();

      // Verify both have same field structure
      assert.ok(nodeKeys.privateKeyHex);
      assert.ok(nodeKeys.publicKeyXHex);
      assert.ok(nodeKeys.publicKeyYHex);
      assert.ok(nodeKeys.publicKeyHex);
      assert.ok(nodeKeys.privateKeyBigInt);
      assert.ok(nodeKeys.publicKeyXBigInt);
      assert.ok(nodeKeys.publicKeyYBigInt);

      assert.ok(crossPlatformKeys.privateKeyHex);
      assert.ok(crossPlatformKeys.publicKeyXHex);
      assert.ok(crossPlatformKeys.publicKeyYHex);
      assert.ok(crossPlatformKeys.publicKeyHex);
      assert.ok(crossPlatformKeys.privateKeyBigInt);
      assert.ok(crossPlatformKeys.publicKeyXBigInt);
      assert.ok(crossPlatformKeys.publicKeyYBigInt);

      // Verify P-256 hex string lengths
      assert.strictEqual(nodeKeys.privateKeyHex.length, 64);
      assert.strictEqual(nodeKeys.publicKeyXHex.length, 64);
      assert.strictEqual(nodeKeys.publicKeyYHex.length, 64);
      assert.strictEqual(nodeKeys.publicKeyHex.length, 130);

      assert.strictEqual(crossPlatformKeys.privateKeyHex.length, 64);
      assert.strictEqual(crossPlatformKeys.publicKeyXHex.length, 64);
      assert.strictEqual(crossPlatformKeys.publicKeyYHex.length, 64);
      assert.strictEqual(crossPlatformKeys.publicKeyHex.length, 130);

      // Verify uncompressed public key format
      assert.strictEqual(
        nodeKeys.publicKeyHex,
        '04' + nodeKeys.publicKeyXHex + nodeKeys.publicKeyYHex
      );
      assert.strictEqual(
        crossPlatformKeys.publicKeyHex,
        '04' + crossPlatformKeys.publicKeyXHex + crossPlatformKeys.publicKeyYHex
      );

      // Verify both work with Secp256r1.fromHex
      const nodePublicKey = Secp256r1.fromHex(nodeKeys.publicKeyHex);
      const crossPlatformPublicKey = Secp256r1.fromHex(crossPlatformKeys.publicKeyHex);
      assert.ok(nodePublicKey);
      assert.ok(crossPlatformPublicKey);
    });
  });
});