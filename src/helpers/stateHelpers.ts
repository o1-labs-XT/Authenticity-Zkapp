import {
  Field,
  Bool,
  UInt8,
  UInt32,
  Provable,
} from 'o1js';

export { PackedImageChainCounters };

/**
 * Helper class for packed image chain state storage operations
 * 
 * Stores 25 chains × 10 bits each = 250 bits total in a single Field
 * Each chain can store 0-1023 images (2^10 - 1)
 */
class PackedImageChainCounters {
  static readonly CHAIN_COUNT = 25;
  static readonly BITS_PER_CHAIN = 10;
  static readonly MAX_PER_CHAIN = 1023; // 2^10 - 1
  static readonly TOTAL_BITS = 250; // 25 * 10

  /**
   * Get the length for a specific chain from packed storage
   * @param field - The packed Field containing all chain lengths  
   * @param chainId - Chain ID (0-24)
   * @returns UInt32 representing the chain length (0-1023)
   */
  static getChainLength(field: Field, chainId: UInt8): UInt32 {
    const bits = field.toBits(254);

    let result = UInt32.from(0);

    // Check each possible chain ID and extract its bits if it matches
    for (let i = 0; i < this.CHAIN_COUNT; i++) {
      const isThisChain = chainId.value.equals(Field.from(i));

      // Extract 10 bits for chain i (bits i*10 to i*10+9)
      const startBit = i * this.BITS_PER_CHAIN;
      const chainBits = bits.slice(startBit, startBit + this.BITS_PER_CHAIN);
      const lengthField = Field.fromBits(chainBits);
      const chainLength = UInt32.fromFields([lengthField]);

      result = Provable.if(isThisChain, chainLength, result);
    }

    return result;
  }

  /**
   * Set the length for a specific chain in packed storage
   * @param field - The packed Field containing all chain lengths
   * @param chainId - Chain ID (0-24)
   * @param newLength - New length value (0-1023)
   * @returns Updated Field with the new chain length
   */
  static setChainLength(field: Field, chainId: UInt8, newLength: UInt32): Field {
    // Validate inputs
    newLength.assertLessThanOrEqual(UInt32.from(this.MAX_PER_CHAIN), 'Length exceeds maximum, it must be ≤ 1023');

    // Get current bits
    const bits = field.toBits(254);

    // Convert new length to bits
    const lengthField = Field.fromFields(newLength.toFields());
    const newBits = lengthField.toBits(this.BITS_PER_CHAIN);

    // Update bits for all 25 chains
    for (let chainIndex = 0; chainIndex < this.CHAIN_COUNT; chainIndex++) {
      const isTargetChain = chainId.value.equals(Field.from(chainIndex));
      const bitStart = chainIndex * this.BITS_PER_CHAIN;

      // Replace the bits for this chain if it's the target chain
      for (let bitIndex = 0; bitIndex < this.BITS_PER_CHAIN; bitIndex++) {
        const currentBit = bits[bitStart + bitIndex];
        const newBit = newBits[bitIndex];
        bits[bitStart + bitIndex] = Provable.if(isTargetChain, newBit, currentBit);
      }
    }

    return Field.fromBits(bits);
  }

  /**
   * Increment a chain's counter by 1
   * @param field - The packed Field containing all chain lengths
   * @param chainId - Chain ID (0-24)
   * @returns Updated Field with incremented counter
   */
  static incrementChain(field: Field, chainId: UInt8): Field {
    // Get current length
    const currentLength = this.getChainLength(field, chainId);

    // Check for overflow before incrementing
    currentLength.assertLessThan(UInt32.from(this.MAX_PER_CHAIN), 'Cannot exceed 1023 images');

    // Increment and update
    const newLength = currentLength.add(UInt32.from(1));
    return this.setChainLength(field, chainId, newLength);
  }

  /**
   * Check if a chain has reached its maximum capacity
   * @param field - The packed Field containing all chain lengths
   * @param chainId - Chain ID (0-24)
   * @returns Bool indicating if chain is at maximum capacity
   */
  static isChainFull(field: Field, chainId: UInt8): Bool {
    const currentLength = this.getChainLength(field, chainId);
    const maxLength = UInt32.from(this.MAX_PER_CHAIN);
    return currentLength.equals(maxLength);
  }

  /**
   * Get the total number of images across all chains
   * @param field - The packed Field containing all chain lengths
   * @returns Total number of images across all 25 chains
   */
  static getTotalImageCount(field: Field): UInt32 {
    // Sum all 25 chains - proper full implementation
    let total = UInt32.from(0);

    for (let i = 0; i < this.CHAIN_COUNT; i++) {
      const chainLength = this.getChainLength(field, UInt8.from(i));
      total = total.add(chainLength);
    }

    return total;
  }
}