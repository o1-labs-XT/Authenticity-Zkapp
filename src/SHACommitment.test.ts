import { Field } from 'o1js';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SHACommitment } from './AuthenticityZkApp.js';

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

    console.log('✓ Round-trip conversion successful');
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

    console.log('✓ Edge cases handled correctly');
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

    console.log('✓ Byte representation is correct');
  });
});
