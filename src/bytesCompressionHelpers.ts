import { Field, Struct, Provable, UInt8 } from 'o1js';
import { Secp256r1 } from './AuthenticityProof.js';
import { Bytes32 } from './commitmentHelpers.js';

export { Secp256r1Commitment, SHACommitment };

/**
 * Compressed representation of a Secp256r1 public key using 4 fields instead of 6.
 *
 * Standard representation: 6 fields (3 for x, 3 for y)
 * Compressed representation: 4 fields (2 for x, 2 for y)
 *
 * Each coordinate (x and y) is 256 bits, which we split into two 128-bit fields,
 * similar to how SHACommitment works.
 */
class Secp256r1Commitment extends Struct({
  xBytes: Bytes32,
  yBytes: Bytes32,
}) {
  /**
   * Creates a Secp256r1Commitment from four 128-bit Field values.
   * This allows storing a public key in 4 fields instead of 6.
   */
  static fromFourFields(
    xHigh128: Field,
    xLow128: Field,
    yHigh128: Field,
    yLow128: Field
  ): Secp256r1Commitment {
    // Verify each Field is within 128-bit range
    const max128 = Field(1n << 128n);
    xHigh128.assertLessThan(max128, 'xHigh128 must be less than 2^128');
    xLow128.assertLessThan(max128, 'xLow128 must be less than 2^128');
    yHigh128.assertLessThan(max128, 'yHigh128 must be less than 2^128');
    yLow128.assertLessThan(max128, 'yLow128 must be less than 2^128');

    // Convert x Fields to bytes
    const xBytes = Provable.witness(Bytes32, () => {
      const highBigInt = xHigh128.toBigInt();
      const lowBigInt = xLow128.toBigInt();

      const highBytes: UInt8[] = [];
      for (let i = 15; i >= 0; i--) {
        const byte = Number((highBigInt >> BigInt(i * 8)) & 0xffn);
        highBytes.push(UInt8.from(byte));
      }

      const lowBytes: UInt8[] = [];
      for (let i = 15; i >= 0; i--) {
        const byte = Number((lowBigInt >> BigInt(i * 8)) & 0xffn);
        lowBytes.push(UInt8.from(byte));
      }

      return Bytes32.from([...highBytes, ...lowBytes]);
    });

    // Convert y Fields to bytes
    const yBytes = Provable.witness(Bytes32, () => {
      const highBigInt = yHigh128.toBigInt();
      const lowBigInt = yLow128.toBigInt();

      const highBytes: UInt8[] = [];
      for (let i = 15; i >= 0; i--) {
        const byte = Number((highBigInt >> BigInt(i * 8)) & 0xffn);
        highBytes.push(UInt8.from(byte));
      }

      const lowBytes: UInt8[] = [];
      for (let i = 15; i >= 0; i--) {
        const byte = Number((lowBigInt >> BigInt(i * 8)) & 0xffn);
        lowBytes.push(UInt8.from(byte));
      }

      return Bytes32.from([...highBytes, ...lowBytes]);
    });

    // Verify the conversion by reconstructing the Fields
    const commitment = new Secp256r1Commitment({ xBytes, yBytes });
    const reconstructed = commitment.toFourFields();
    xHigh128.assertEquals(reconstructed.xHigh128);
    xLow128.assertEquals(reconstructed.xLow128);
    yHigh128.assertEquals(reconstructed.yHigh128);
    yLow128.assertEquals(reconstructed.yLow128);

    return commitment;
  }

  /**
   * Creates a Secp256r1Commitment from a public key.
   */
  static fromPublicKey(publicKey: Secp256r1): Secp256r1Commitment {
    return Provable.witness(Secp256r1Commitment, () => {
      // Secp256r1 coordinates are 256 bits each
      // We need to convert them to bytes

      // Convert x coordinate to bytes
      const xBigInt = publicKey.x.toBigInt();
      const xByteArray: UInt8[] = [];
      for (let i = 31; i >= 0; i--) {
        const byte = Number((xBigInt >> BigInt(i * 8)) & 0xffn);
        xByteArray.push(UInt8.from(byte));
      }
      const xBytes = Bytes32.from(xByteArray);

      // Convert y coordinate to bytes
      const yBigInt = publicKey.y.toBigInt();
      const yByteArray: UInt8[] = [];
      for (let i = 31; i >= 0; i--) {
        const byte = Number((yBigInt >> BigInt(i * 8)) & 0xffn);
        yByteArray.push(UInt8.from(byte));
      }
      const yBytes = Bytes32.from(yByteArray);

      return new Secp256r1Commitment({ xBytes, yBytes });
    });
  }

  /**
   * Splits the commitment into four 128-bit Field values.
   */
  toFourFields(): {
    xHigh128: Field;
    xLow128: Field;
    yHigh128: Field;
    yLow128: Field;
  } {
    // Extract x coordinate fields
    const xByteArray = this.xBytes.bytes;
    let xHigh128 = Field(0);
    for (let i = 0; i < 16; i++) {
      const byte = xByteArray[i];
      xHigh128 = xHigh128.mul(256).add(byte.value);
    }

    let xLow128 = Field(0);
    for (let i = 16; i < 32; i++) {
      const byte = xByteArray[i];
      xLow128 = xLow128.mul(256).add(byte.value);
    }

    // Extract y coordinate fields
    const yByteArray = this.yBytes.bytes;
    let yHigh128 = Field(0);
    for (let i = 0; i < 16; i++) {
      const byte = yByteArray[i];
      yHigh128 = yHigh128.mul(256).add(byte.value);
    }

    let yLow128 = Field(0);
    for (let i = 16; i < 32; i++) {
      const byte = yByteArray[i];
      yLow128 = yLow128.mul(256).add(byte.value);
    }

    return { xHigh128, xLow128, yHigh128, yLow128 };
  }

  /**
   * Reconstructs the Secp256r1 public key from the commitment.
   * This would be used off-chain to recover the full key.
   */
  toPublicKey(): Secp256r1 {
    return Provable.witness(Secp256r1, () => {
      // Convert x bytes to bigint
      const xByteArray = this.xBytes.bytes;
      let xBigInt = 0n;
      for (let i = 0; i < 32; i++) {
        xBigInt = (xBigInt << 8n) | BigInt(xByteArray[i].toNumber());
      }

      // Convert y bytes to bigint
      const yByteArray = this.yBytes.bytes;
      let yBigInt = 0n;
      for (let i = 0; i < 32; i++) {
        yBigInt = (yBigInt << 8n) | BigInt(yByteArray[i].toNumber());
      }

      return new Secp256r1({ x: xBigInt, y: yBigInt });
    });
  }
}

class SHACommitment extends Struct({
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
