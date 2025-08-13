import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  hashImageOffCircuit,
  computeOnChainCommitment,
  hashImageOffCircuitCrossPlatform,
  computeOnChainCommitmentCrossPlatform,
} from './commitmentHelpers.js';
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
        const nodeCommitment = computeOnChainCommitment(inputBuffer);
        
        // Get commitment from cross-platform implementation
        const crossPlatformCommitment = await computeOnChainCommitmentCrossPlatform(inputUint8Array);
        
        // Verify they match
        assert.strictEqual(
          crossPlatformCommitment.toBigInt().toString(),
          nodeCommitment.toBigInt().toString()
        );
        
        // Also verify against the expected value from test vectors
        assert.strictEqual(nodeCommitment.toBigInt().toString(), expectedCommitment);
        assert.strictEqual(crossPlatformCommitment.toBigInt().toString(), expectedCommitment);
      });
    });
  });
});