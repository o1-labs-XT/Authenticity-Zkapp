import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { UInt32, UInt8, Provable } from 'o1js';
import {
  AuthenticityProgram,
  AuthenticityInputs,
  Ecdsa,
  Secp256r1,
} from './AuthenticityProof.js';
import {
  Bytes32,
  FinalRoundInputs,
  hashUntilFinalRound,
  generateECKeyPair,
} from './commitmentHelpers.js';

describe('AuthenticityProof', () => {
  before(async () => {
    console.log('Compiling AuthenticityProgram...');
    await AuthenticityProgram.compile();
    console.log('Compilation complete');
  });

  describe('Valid cases', () => {
    it('should verify authenticity with valid commitment and signature', async () => {
      // Create test data
      const testData = Buffer.from('Hello, zkApp world!');

      // Generate keys for signing
      const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);
      // Hash the data until final round
      const { penultimateState, finalRoundInputs, expectedHash } =
        hashUntilFinalRound(testData);

      // Convert to o1js types
      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      // Create commitment from expected hash
      const commitment = Bytes32.fromHex(expectedHash);

      // Sign the commitment
      //const signature = Signature.create(privateKey, commitment.toFields());
      const signature = Ecdsa.signHash(commitment, privateKey.toBigInt());
      // Create public inputs
      const publicInputs = new AuthenticityInputs({
        commitment: commitment,
        signature,
        publicKey,
      });

      // Create private inputs
      const privateInputs = new FinalRoundInputs({
        state: penultimateStateUInt32,
        initialState: initialStateUInt32,
        messageWord: UInt32.from(finalRoundInputs.messageWord),
        roundConstant: UInt32.from(finalRoundInputs.roundConstant),
      });

      // Generate proof
      const { proof } = await AuthenticityProgram.verifyAuthenticity(
        publicInputs,
        privateInputs
      );

      // Verify the proof
      const isValid = await AuthenticityProgram.verify(proof);
      assert.equal(isValid, true);
    });

    it('should work with different data sizes', async () => {
      const testCases = [
        Buffer.from(''), // Empty data
        Buffer.from('a'), // Single byte
        Buffer.from('a'.repeat(55)), // Just under one block
        Buffer.from('a'.repeat(64)), // Exactly one block
        Buffer.from('a'.repeat(119)), // Just under two blocks
        Buffer.from('a'.repeat(128)), // Exactly two blocks
      ];

      for (const testData of testCases) {
        const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
        const publicKey = Secp256r1.fromHex(publicKeyHex);
        const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);

        const { penultimateState, finalRoundInputs, expectedHash } =
          hashUntilFinalRound(testData);

        const penultimateStateUInt32 = penultimateState.map((x) =>
          UInt32.from(x)
        ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
        const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
          UInt32.from(x)
        ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

        const commitment = Bytes32.fromHex(expectedHash);
        const signature = Ecdsa.signHash(commitment, privateKey.toBigInt());

        const publicInputs = new AuthenticityInputs({
          commitment: commitment,
          signature,
          publicKey,
        });

        const privateInputs = new FinalRoundInputs({
          state: penultimateStateUInt32,
          initialState: initialStateUInt32,
          messageWord: UInt32.from(finalRoundInputs.messageWord),
          roundConstant: UInt32.from(finalRoundInputs.roundConstant),
        });

        const { proof } = await AuthenticityProgram.verifyAuthenticity(
          publicInputs,
          privateInputs
        );

        const isValid = await AuthenticityProgram.verify(proof);
        assert.equal(isValid, true);
      }
    });
  });

  describe('Negative cases', () => {
    it('should fail with incorrect commitment', async () => {
      const testData = Buffer.from('Hello, zkApp world!');
      const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);

      const { penultimateState, finalRoundInputs } =
        hashUntilFinalRound(testData);

      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      // Create wrong commitment
      const wrongCommitment = Bytes32.fromHex(
        '0000000000000000000000000000000000000000000000000000000000000000'
      );
      const signature = Ecdsa.signHash(wrongCommitment, privateKey.toBigInt());

      const publicInputs = new AuthenticityInputs({
        commitment: wrongCommitment,
        signature,
        publicKey,
      });

      const privateInputs = new FinalRoundInputs({
        state: penultimateStateUInt32,
        initialState: initialStateUInt32,
        messageWord: UInt32.from(finalRoundInputs.messageWord),
        roundConstant: UInt32.from(finalRoundInputs.roundConstant),
      });

      await assert.rejects(
        AuthenticityProgram.verifyAuthenticity(publicInputs, privateInputs),
        'Expected proof generation to fail'
      );
    });

    it('should fail with invalid signature', async () => {
      const testData = Buffer.from('Hello, zkApp world!');
      const { publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);

      const { penultimateState, finalRoundInputs, expectedHash } =
        hashUntilFinalRound(testData);

      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const commitment = Bytes32.fromHex(expectedHash);

      // Create signature with different private key
      const wrongPrivateKey = Secp256r1.Scalar.from(
        generateECKeyPair().privateKeyBigInt
      );
      const wrongSignature = Ecdsa.signHash(
        commitment,
        wrongPrivateKey.toBigInt()
      );

      const publicInputs = new AuthenticityInputs({
        commitment: commitment,
        signature: wrongSignature,
        publicKey, // Using original public key
      });

      const privateInputs = new FinalRoundInputs({
        state: penultimateStateUInt32,
        initialState: initialStateUInt32,
        messageWord: UInt32.from(finalRoundInputs.messageWord),
        roundConstant: UInt32.from(finalRoundInputs.roundConstant),
      });

      await assert.rejects(
        AuthenticityProgram.verifyAuthenticity(publicInputs, privateInputs),
        'Expected proof generation to fail'
      );
    });

    it('should fail with wrong final round inputs', async () => {
      const testData = Buffer.from('Hello, zkApp world!');
      const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);

      const { penultimateState, finalRoundInputs, expectedHash } =
        hashUntilFinalRound(testData);

      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const commitment = Bytes32.fromHex(expectedHash);
      const signature = Ecdsa.signHash(commitment, privateKey.toBigInt());

      const publicInputs = new AuthenticityInputs({
        commitment: commitment,
        signature,
        publicKey,
      });

      // Modify the message word to create invalid inputs
      const privateInputs = new FinalRoundInputs({
        state: penultimateStateUInt32,
        initialState: initialStateUInt32,
        messageWord: UInt32.from(finalRoundInputs.messageWord + 1), // Wrong value
        roundConstant: UInt32.from(finalRoundInputs.roundConstant),
      });

      await assert.rejects(
        AuthenticityProgram.verifyAuthenticity(publicInputs, privateInputs),
        'Expected proof generation to fail'
      );
    });

    it('should fail with tampered state', async () => {
      const testData = Buffer.from('Hello, zkApp world!');
      const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);

      const { penultimateState, finalRoundInputs, expectedHash } =
        hashUntilFinalRound(testData);

      // Tamper with the penultimate state
      const tamperedState = [...penultimateState];
      tamperedState[0] = (tamperedState[0] + 1) >>> 0;

      const tamperedStateUInt32 = tamperedState.map((x) => UInt32.from(x)) as [
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32
      ];
      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const commitment = Bytes32.fromHex(expectedHash);
      const signature = Ecdsa.signHash(commitment, privateKey.toBigInt());

      const publicInputs = new AuthenticityInputs({
        commitment: commitment,
        signature,
        publicKey,
      });

      const privateInputs = new FinalRoundInputs({
        state: tamperedStateUInt32,
        initialState: initialStateUInt32,
        messageWord: UInt32.from(finalRoundInputs.messageWord),
        roundConstant: UInt32.from(finalRoundInputs.roundConstant),
      });

      await assert.rejects(
        AuthenticityProgram.verifyAuthenticity(publicInputs, privateInputs),
        'Expected proof generation to fail'
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle maximum values in state', async () => {
      const testData = Buffer.from('Test with max values');
      const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);

      const { penultimateState, finalRoundInputs, expectedHash } =
        hashUntilFinalRound(testData);

      // Test that our conversion handles maximum UInt32 values correctly
      const maxUInt32 = 0xffffffff;
      const testState = [
        maxUInt32,
        0,
        maxUInt32,
        0,
        maxUInt32,
        0,
        maxUInt32,
        0,
      ];

      const testStateUInt32 = testState.map((x) => UInt32.from(x)) as [
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32
      ];

      // Verify that the conversion maintains the values
      for (let i = 0; i < 8; i++) {
        assert.equal(testStateUInt32[i].toBigint(), BigInt(testState[i]));
      }

      // Also verify the actual circuit works with the real data
      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      const commitment = Bytes32.fromHex(expectedHash);
      const signature = Ecdsa.signHash(commitment, privateKey.toBigInt());

      const publicInputs = new AuthenticityInputs({
        commitment: commitment,
        signature,
        publicKey,
      });

      const privateInputs = new FinalRoundInputs({
        state: penultimateStateUInt32,
        initialState: initialStateUInt32,
        messageWord: UInt32.from(finalRoundInputs.messageWord),
        roundConstant: UInt32.from(finalRoundInputs.roundConstant),
      });

      const { proof } = await AuthenticityProgram.verifyAuthenticity(
        publicInputs,
        privateInputs
      );

      const isValid = await AuthenticityProgram.verify(proof);
      assert.equal(isValid, true);
    });

    it('should correctly convert hash to bytes', async () => {
      // Test the conversion logic with known values
      const itHashValues = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19,
      ];

      const hashUInt32 = itHashValues.map((x) => UInt32.from(x)) as [
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32,
        UInt32
      ];

      // Perform the same conversion as in the circuit
      const hashBytes: UInt8[] = [];
      for (let i = 0; i < 8; i++) {
        const bytes = hashUInt32[i].toBytesBE();
        hashBytes.push(...bytes);
      }

      const computedHash = Bytes32.from(hashBytes);

      // Expected hex representation
      const expectedHex =
        '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
      const expectedBytes = Bytes32.fromHex(expectedHex);

      // Compare the bytes
      Provable.assertEqual(computedHash, expectedBytes);
    });
  });
});
