import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { UInt32 } from 'o1js';
import * as fs from 'fs';
import * as path from 'path';
import {
  Bytes32,
  hashUntilFinalRound,
  performFinalSHA256Round,
  hashImageOffCircuit,
  prepareImageVerification,
} from './commitmentHelpers.js';

describe('commitmentHelpers', () => {
  // Note: The performFinalSHA256Round function uses UInt32.add() which enforces
  // that results fit in 32 bits, but SHA-256 requires modular arithmetic (mod 2^32).
  // This causes the tests to fail when additions overflow.
  // The circuit implementation would need to use modular addition to match
  // the off-circuit SHA-256 implementation.
  // Test data
  const testData = Buffer.from('Hello, World!');
  const largeTestData = Buffer.from('a'.repeat(1000));
  const emptyData = Buffer.alloc(0);

  describe('hashUntilFinalRound + performFinalSHA256Round', () => {
    it('should produce the same output as hashImageOffCircuit', () => {
      // Get the result from hashImageOffCircuit
      const expectedHash = hashImageOffCircuit(testData);

      // Get the intermediate state from hashUntilFinalRound
      const {
        penultimateState,
        finalRoundInputs,
        expectedHash: expectedHashFromFunc,
      } = hashUntilFinalRound(testData);

      // Verify that hashUntilFinalRound also computes the correct expected hash
      assert.strictEqual(expectedHashFromFunc, expectedHash);

      // Convert to UInt32 types for performFinalSHA256Round
      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const messageWord = UInt32.from(finalRoundInputs.messageWord);
      const roundConstant = UInt32.from(finalRoundInputs.roundConstant);

      // Perform the final round
      const finalHash = performFinalSHA256Round(
        penultimateStateUInt32,
        initialStateUInt32,
        messageWord,
        roundConstant
      );

      // Convert final hash to hex string
      // Need to handle the conversion carefully since UInt32 values in o1js
      // are represented as field elements
      const hashWords = finalHash.map((word) => {
        // Convert to bigint and ensure it's within 32-bit range
        const value = word.toBigint();
        return value & 0xffffffffn; // Mask to 32 bits
      });
      const hashHex = hashWords
        .map((word) => word.toString(16).padStart(8, '0'))
        .join('');

      // Compare with expected hash
      assert.strictEqual(hashHex, expectedHash);
    });

    it('should handle empty data correctly', () => {
      const expectedHash = hashImageOffCircuit(emptyData);

      const { penultimateState, finalRoundInputs } =
        hashUntilFinalRound(emptyData);

      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const messageWord = UInt32.from(finalRoundInputs.messageWord);
      const roundConstant = UInt32.from(finalRoundInputs.roundConstant);

      const finalHash = performFinalSHA256Round(
        penultimateStateUInt32,
        initialStateUInt32,
        messageWord,
        roundConstant
      );

      const hashWords = finalHash.map((word) => {
        const value = word.toBigint();
        return value & 0xffffffffn;
      });
      const hashHex = hashWords
        .map((word) => word.toString(16).padStart(8, '0'))
        .join('');

      assert.strictEqual(hashHex, expectedHash);
    });

    it('should handle large data correctly', () => {
      const expectedHash = hashImageOffCircuit(largeTestData);

      const { penultimateState, finalRoundInputs } =
        hashUntilFinalRound(largeTestData);

      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const messageWord = UInt32.from(finalRoundInputs.messageWord);
      const roundConstant = UInt32.from(finalRoundInputs.roundConstant);

      const finalHash = performFinalSHA256Round(
        penultimateStateUInt32,
        initialStateUInt32,
        messageWord,
        roundConstant
      );

      const hashWords = finalHash.map((word) => {
        const value = word.toBigint();
        return value & 0xffffffffn;
      });
      const hashHex = hashWords
        .map((word) => word.toString(16).padStart(8, '0'))
        .join('');

      assert.strictEqual(hashHex, expectedHash);
    });

    it('should correctly prepare state for final round', () => {
      const { penultimateState, finalRoundInputs, expectedHash } =
        hashUntilFinalRound(testData);

      // Verify the function returns all required fields
      assert.ok(penultimateState);
      assert.ok(finalRoundInputs);
      assert.ok(expectedHash);

      // Verify penultimate state has 8 32-bit values
      assert.strictEqual(penultimateState.length, 8);
      penultimateState.forEach((value) => {
        assert.ok(value >= 0 && value <= 0xffffffff);
      });

      // Verify initial state has 8 32-bit values
      assert.strictEqual(finalRoundInputs.initialState.length, 8);
      finalRoundInputs.initialState.forEach((value) => {
        assert.ok(value >= 0 && value <= 0xffffffff);
      });

      // Verify message word and round constant are 32-bit values
      assert.ok(
        finalRoundInputs.messageWord >= 0 &&
          finalRoundInputs.messageWord <= 0xffffffff
      );
      assert.ok(
        finalRoundInputs.roundConstant >= 0 &&
          finalRoundInputs.roundConstant <= 0xffffffff
      );

      // Verify expected hash matches off-circuit computation
      assert.strictEqual(expectedHash, hashImageOffCircuit(testData));
    });
  });

  describe('prepareImageVerification', () => {
    it('should prepare verification inputs correctly', () => {
      // Create a temporary test file
      const testFilePath = path.join(process.cwd(), 'test-image.tmp');
      fs.writeFileSync(testFilePath, testData);

      try {
        const result = prepareImageVerification(testFilePath);

        // Verify the expected hash matches
        const expectedHash = hashImageOffCircuit(testData);
        assert.strictEqual(result.expectedHashHex, expectedHash);
        assert.strictEqual(result.expectedHash.toHex(), expectedHash);

        // Verify all required fields are present
        assert.ok(result.penultimateState);
        assert.ok(result.initialState);
        assert.ok(result.messageWord);
        assert.ok(result.roundConstant);
        assert.strictEqual(result.penultimateState.length, 8);
        assert.strictEqual(result.initialState.length, 8);

        // Verify types are correct
        result.penultimateState.forEach((state) => {
          assert.ok(state instanceof UInt32);
        });
        result.initialState.forEach((state) => {
          assert.ok(state instanceof UInt32);
        });
        assert.ok(result.messageWord instanceof UInt32);
        assert.ok(result.roundConstant instanceof UInt32);
        assert.ok(result.expectedHash instanceof Bytes32);
      } finally {
        // Clean up test file
        fs.unlinkSync(testFilePath);
      }
    });
  });
});
