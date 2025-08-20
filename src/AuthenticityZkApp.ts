import {
  PublicKey,
  method,
  TokenContract,
  UInt64,
  AccountUpdate,
  AccountUpdateForest,
  Bool,
  Poseidon,
  Field,
  Struct,
  UInt8,
  Provable,
} from 'o1js';

import { Bytes32 } from './commitmentHelpers.js';

import { AuthenticityProof, AuthenticityInputs } from './AuthenticityProof.js';

export class SHACommitment extends Struct({
  bytes: Bytes32,
}) {
  /**
   * Creates a SHACommitment from two 128-bit Field values.
   * Each Field must be < 2^128 to ensure the total represents exactly 256 bits.
   */
  static fromTwoFields(high128: Field, low128: Field): SHACommitment {
    // Verify each Field is within 128-bit range
    const max128 = Field(1n << 128n);
    high128.assertLessThan(max128, 'high128 must be less than 2^128');
    low128.assertLessThan(max128, 'low128 must be less than 2^128');

    // Convert Fields to bytes using witness
    const bytes = Provable.witness(Bytes32, () => {
      // Convert Fields to bigints for byte extraction
      const highBigInt = high128.toBigInt();
      const lowBigInt = low128.toBigInt();

      // Extract bytes from high128 (big-endian)
      const highBytes: UInt8[] = [];
      for (let i = 15; i >= 0; i--) {
        const byte = Number((highBigInt >> BigInt(i * 8)) & 0xffn);
        highBytes.push(UInt8.from(byte));
      }

      // Extract bytes from low128 (big-endian)
      const lowBytes: UInt8[] = [];
      for (let i = 15; i >= 0; i--) {
        const byte = Number((lowBigInt >> BigInt(i * 8)) & 0xffn);
        lowBytes.push(UInt8.from(byte));
      }

      // Combine into 32 bytes
      return Bytes32.from([...highBytes, ...lowBytes]);
    });

    // Verify the conversion by reconstructing the Fields
    const reconstructed = new SHACommitment({ bytes }).toTwoFields();
    high128.assertEquals(reconstructed.high128);
    low128.assertEquals(reconstructed.low128);

    return new SHACommitment({ bytes });
  }

  /**
   * Splits the 32-byte commitment into two 128-bit Field values.
   */
  toTwoFields(): { high128: Field; low128: Field } {
    // Get the raw bytes as an array
    const byteArray = this.bytes.bytes;

    // Extract high 128 bits (first 16 bytes)
    let high128 = Field(0);
    for (let i = 0; i < 16; i++) {
      const byte = byteArray[i];
      // Shift left by 8 bits and add the byte
      high128 = high128.mul(256).add(byte.value);
    }

    // Extract low 128 bits (last 16 bytes)
    let low128 = Field(0);
    for (let i = 16; i < 32; i++) {
      const byte = byteArray[i];
      // Shift left by 8 bits and add the byte
      low128 = low128.mul(256).add(byte.value);
    }

    return { high128, low128 };
  }

  /**
   * Converts the commitment to a hex string.
   */
  toHex(): string {
    return this.bytes.toHex();
  }
}

/**
 * ZkApp that verifies authenticity proofs and stores metadata on-chain.
 *
 * Metadata to store:
 *  - Hash/commitment of the digital asset
 *  - Creator's public key
 */
export class AuthenticityZkApp extends TokenContract {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async approveBase(forest: AccountUpdateForest) {
    throw Error(
      'transfers of tokens are not allowed, change the owner instead'
    );
  }

  @method async verifyAndStore(
    address: PublicKey, // Address of the new token account
    proof: AuthenticityProof,
    inputs: AuthenticityInputs
  ) {
    // Check the inputs
    const creator = proof.publicInput.publicKey;
    inputs.publicKey.assertEquals(creator);
    inputs.signature.assertEquals(proof.publicInput.signature);
    Poseidon.hash(proof.publicInput.commitment.toFields()).assertEquals(
      Poseidon.hash(inputs.commitment.toFields())
    );

    // Verify the provided proof using the AuthenticityProgram
    proof.verify();

    // Mint a token with the image metadata
    const tokenId = this.deriveTokenId();
    const update = AccountUpdate.createSigned(address, tokenId);
    update.account.isNew.getAndRequireEquals().assertTrue();

    this.internal.mint({
      address,
      amount: UInt64.from(1),
    });

    const shaCommitment = new SHACommitment({
      bytes: new Bytes32(inputs.commitment.bytes),
    });
    const { high128, low128 } = shaCommitment.toTwoFields();

    // Set the on-chain state of the token account
    update.body.update.appState[0] = {
      isSome: Bool(true),
      value: Field(1), // Token Schema Version
    };
    update.body.update.appState[1] = {
      isSome: Bool(true),
      value: high128, // High 128 bits of the SHA commitment
    };
    update.body.update.appState[2] = {
      isSome: Bool(true),
      value: low128, // Low 128 bits of the SHA commitment
    };
    update.body.update.appState[3] = {
      isSome: Bool(true),
      value: creator.x, // Creator's public key X coordinate
    };
    update.body.update.appState[4] = {
      isSome: Bool(true),
      value: creator.isOdd.toField(), // Creator's public key isOdd
    };
  }
}
