import { Field } from 'o1js';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SHACommitment, Secp256r1Commitment } from '../helpers/bytesCompressionHelpers.js';
import { Secp256r1 } from '../AuthenticityProof.js';
import { generateECKeyPair } from '../helpers/commitmentHelpers.js';

describe('Bytes Compression Helpers', () => {
  describe('SHACommitment', () => {
    it('should correctly convert between Fields and Bytes32', async () => {
      // Test with some sample 128-bit values
      const high128 = Field(0x123456789abcdef0123456789abcdefn); // Example 128-bit value
      const low128 = Field(0xfedcba9876543210fedcba9876543210n); // Example 128-bit value

      // Create SHACommitment from two Fields
      const commitment = SHACommitment.fromTwoFields(high128, low128);

      // Convert back to Fields
      const reconstructed = commitment.toTwoFields();

      // Verify round-trip conversion
      assert.strictEqual(reconstructed.high128.toBigInt(), high128.toBigInt());
      assert.strictEqual(reconstructed.low128.toBigInt(), low128.toBigInt());

      console.log('✓ SHACommitment: Round-trip conversion successful');
    });

    it('should correctly handle edge cases', async () => {
      // Test with zero values
      const zero = Field(0);
      const commitment1 = SHACommitment.fromTwoFields(zero, zero);
      const result1 = commitment1.toTwoFields();
      assert.strictEqual(result1.high128.toBigInt(), 0n);
      assert.strictEqual(result1.low128.toBigInt(), 0n);

      // Test with max 128-bit values
      const max128 = Field((1n << 128n) - 1n);
      const commitment2 = SHACommitment.fromTwoFields(max128, max128);
      const result2 = commitment2.toTwoFields();
      assert.strictEqual(result2.high128.toBigInt(), max128.toBigInt());
      assert.strictEqual(result2.low128.toBigInt(), max128.toBigInt());

      console.log('✓ SHACommitment: Edge cases handled correctly');
    });

    it('should produce correct byte representation', async () => {
      // Test a known value
      const high = Field(0x0123456789abcdef0123456789abcdefn);
      const low = Field(0xfedcba9876543210fedcba9876543210n);

      const commitment = SHACommitment.fromTwoFields(high, low);
      const hex = commitment.toHex();

      // The hex should be the concatenation of high and low in big-endian
      const expectedHex =
        '0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210';
      assert.strictEqual(hex, expectedHex);

      console.log('✓ SHACommitment: Byte representation is correct');
    });

    it('should reject values larger than 128 bits', async () => {
      const tooLarge = Field(1n << 128n); // 2^128, which is too large
      const valid = Field(0);

      assert.throws(() => {
        SHACommitment.fromTwoFields(tooLarge, valid);
      }, /high128 must be less than 2\^128/);

      assert.throws(() => {
        SHACommitment.fromTwoFields(valid, tooLarge);
      }, /low128 must be less than 2\^128/);

      console.log('✓ SHACommitment: Correctly rejects oversized values');
    });
  });

  describe('Secp256r1Commitment', () => {
    it('should correctly convert between four Fields', async () => {
      // Test with sample 128-bit values for each component
      const xHigh128 = Field(0x123456789abcdef0123456789abcdefn);
      const xLow128 = Field(0xfedcba9876543210fedcba9876543210n);
      const yHigh128 = Field(0xabcdef0123456789abcdef0123456789n);
      const yLow128 = Field(0x76543210fedcba9876543210fedcba98n);

      // Create commitment from four Fields
      const commitment = Secp256r1Commitment.fromFourFields(
        xHigh128,
        xLow128,
        yHigh128,
        yLow128
      );

      // Convert back to Fields
      const reconstructed = commitment.toFourFields();

      // Verify round-trip conversion
      assert.strictEqual(reconstructed.xHigh128.toBigInt(), xHigh128.toBigInt());
      assert.strictEqual(reconstructed.xLow128.toBigInt(), xLow128.toBigInt());
      assert.strictEqual(reconstructed.yHigh128.toBigInt(), yHigh128.toBigInt());
      assert.strictEqual(reconstructed.yLow128.toBigInt(), yLow128.toBigInt());

      console.log('✓ Secp256r1Commitment: Four fields round-trip successful');
    });

    it('should correctly compress and decompress a public key', async () => {
      // Generate a real Secp256r1 key pair
      const { publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);

      // Create commitment from public key
      const commitment = Secp256r1Commitment.fromPublicKey(publicKey);

      // Convert to four fields
      const { xHigh128, xLow128, yHigh128, yLow128 } = commitment.toFourFields();

      // Verify each field is within 128-bit range
      const max128 = 1n << 128n;
      assert(xHigh128.toBigInt() < max128, 'xHigh128 exceeds 128 bits');
      assert(xLow128.toBigInt() < max128, 'xLow128 exceeds 128 bits');
      assert(yHigh128.toBigInt() < max128, 'yHigh128 exceeds 128 bits');
      assert(yLow128.toBigInt() < max128, 'yLow128 exceeds 128 bits');

      // Reconstruct commitment from fields
      const reconstructedCommitment = Secp256r1Commitment.fromFourFields(
        xHigh128,
        xLow128,
        yHigh128,
        yLow128
      );

      // Verify the bytes match
      const originalXBytes = commitment.xBytes.bytes;
      const reconstructedXBytes = reconstructedCommitment.xBytes.bytes;
      const originalYBytes = commitment.yBytes.bytes;
      const reconstructedYBytes = reconstructedCommitment.yBytes.bytes;

      for (let i = 0; i < 32; i++) {
        assert.strictEqual(
          originalXBytes[i].toBigInt(),
          reconstructedXBytes[i].toBigInt(),
          `X byte ${i} mismatch`
        );
        assert.strictEqual(
          originalYBytes[i].toBigInt(),
          reconstructedYBytes[i].toBigInt(),
          `Y byte ${i} mismatch`
        );
      }

      console.log('✓ Secp256r1Commitment: Public key compression successful');
    });

    it('should handle edge cases for Secp256r1', async () => {
      // Test with zero values
      const zero = Field(0);
      const commitment1 = Secp256r1Commitment.fromFourFields(zero, zero, zero, zero);
      const result1 = commitment1.toFourFields();
      assert.strictEqual(result1.xHigh128.toBigInt(), 0n);
      assert.strictEqual(result1.xLow128.toBigInt(), 0n);
      assert.strictEqual(result1.yHigh128.toBigInt(), 0n);
      assert.strictEqual(result1.yLow128.toBigInt(), 0n);

      // Test with max 128-bit values
      const max128 = Field((1n << 128n) - 1n);
      const commitment2 = Secp256r1Commitment.fromFourFields(
        max128,
        max128,
        max128,
        max128
      );
      const result2 = commitment2.toFourFields();
      assert.strictEqual(result2.xHigh128.toBigInt(), max128.toBigInt());
      assert.strictEqual(result2.xLow128.toBigInt(), max128.toBigInt());
      assert.strictEqual(result2.yHigh128.toBigInt(), max128.toBigInt());
      assert.strictEqual(result2.yLow128.toBigInt(), max128.toBigInt());

      console.log('✓ Secp256r1Commitment: Edge cases handled correctly');
    });

    it('should reject values larger than 128 bits', async () => {
      const tooLarge = Field(1n << 128n); // 2^128, which is too large
      const valid = Field(0);

      assert.throws(() => {
        Secp256r1Commitment.fromFourFields(tooLarge, valid, valid, valid);
      }, /xHigh128 must be less than 2\^128/);

      assert.throws(() => {
        Secp256r1Commitment.fromFourFields(valid, tooLarge, valid, valid);
      }, /xLow128 must be less than 2\^128/);

      assert.throws(() => {
        Secp256r1Commitment.fromFourFields(valid, valid, tooLarge, valid);
      }, /yHigh128 must be less than 2\^128/);

      assert.throws(() => {
        Secp256r1Commitment.fromFourFields(valid, valid, valid, tooLarge);
      }, /yLow128 must be less than 2\^128/);

      console.log('✓ Secp256r1Commitment: Correctly rejects oversized values');
    });

    it('should correctly store Secp256r1 key in 4 fields instead of 6', async () => {
      // Generate a key
      const { publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      
      // Original storage: 6 fields (3 for x, 3 for y)
      const originalFields = [
        ...publicKey.x.toFields(),
        ...publicKey.y.toFields()
      ];
      assert.strictEqual(originalFields.length, 6, 'Original uses 6 fields');

      // Compressed storage: 4 fields
      const commitment = Secp256r1Commitment.fromPublicKey(publicKey);
      const { xHigh128, xLow128, yHigh128, yLow128 } = commitment.toFourFields();
      const compressedFields = [xHigh128, xLow128, yHigh128, yLow128];
      assert.strictEqual(compressedFields.length, 4, 'Compressed uses 4 fields');

      console.log('✓ Secp256r1Commitment: Storage reduced from 6 to 4 fields (33% reduction)');
    });

    it('should maintain consistency across multiple conversions', async () => {
      const { publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      
      // First conversion
      const commitment1 = Secp256r1Commitment.fromPublicKey(publicKey);
      const fields1 = commitment1.toFourFields();
      
      // Second conversion from the same key
      const commitment2 = Secp256r1Commitment.fromPublicKey(publicKey);
      const fields2 = commitment2.toFourFields();
      
      // Both should produce identical results
      assert.strictEqual(
        fields1.xHigh128.toBigInt(),
        fields2.xHigh128.toBigInt(),
        'xHigh128 should be consistent'
      );
      assert.strictEqual(
        fields1.xLow128.toBigInt(),
        fields2.xLow128.toBigInt(),
        'xLow128 should be consistent'
      );
      assert.strictEqual(
        fields1.yHigh128.toBigInt(),
        fields2.yHigh128.toBigInt(),
        'yHigh128 should be consistent'
      );
      assert.strictEqual(
        fields1.yLow128.toBigInt(),
        fields2.yLow128.toBigInt(),
        'yLow128 should be consistent'
      );
      
      console.log('✓ Secp256r1Commitment: Consistent conversions verified');
    });

    it('should correctly regenerate Secp256r1 from hex using 4 fields', async () => {
      // Generate a valid Secp256r1 key pair
      const { publicKeyHex } = generateECKeyPair();
      
      // Convert hex to Secp256r1
      const originalKey = Secp256r1.fromHex(publicKeyHex);
      console.log('Original key x:', originalKey.x.toBigInt());
      console.log('Original key y:', originalKey.y.toBigInt());
      
      // Compress to commitment
      const commitment = Secp256r1Commitment.fromPublicKey(originalKey);
      
      // Extract the 4 fields
      const { xHigh128, xLow128, yHigh128, yLow128 } = commitment.toFourFields();
      console.log('\nCompressed to 4 fields:');
      console.log('xHigh128:', xHigh128.toBigInt());
      console.log('xLow128:', xLow128.toBigInt());
      console.log('yHigh128:', yHigh128.toBigInt());
      console.log('yLow128:', yLow128.toBigInt());
      
      // Reconstruct commitment from fields
      const reconstructedCommitment = Secp256r1Commitment.fromFourFields(
        xHigh128,
        xLow128,
        yHigh128,
        yLow128
      );
      
      // Reconstruct the key
      const reconstructedKey = reconstructedCommitment.toPublicKey();
      console.log('\nReconstructed key x:', reconstructedKey.x.toBigInt());
      console.log('Reconstructed key y:', reconstructedKey.y.toBigInt());
      
      // Verify they match
      assert.strictEqual(
        reconstructedKey.x.toBigInt(),
        originalKey.x.toBigInt(),
        'X coordinate should match'
      );
      assert.strictEqual(
        reconstructedKey.y.toBigInt(),
        originalKey.y.toBigInt(),
        'Y coordinate should match'
      );
      
      // Verify the reconstructed key has the same coordinates
      // Note: Secp256r1 doesn't have a toHex() method, so we verify by coordinates
      
      console.log('\n✓ Secp256r1Commitment: Successfully regenerated Secp256r1 from hex using 4 fields');
    });
  });
});