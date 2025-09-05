// VK Hash: 2500344745592430268173091005144987605594334572818740634112428059802822161761
import {
  SmartContract,
  state,
  State,
  Field,
  method,
} from 'o1js';

export { TokenAccountContract };

/**
 * Smart contract for individual authenticity tokens.
 * State layout (6 fields total):
 * 0-1: SHA hash of image content (high/low 128 bits)
 * 2-5: SECP256r1 creator public key who signed the image (x_high, x_low, y_high, y_low)
 */
class TokenAccountContract extends SmartContract {
  @state(Field) shaHashHigh = State<Field>();        // Field 0: High 128 bits of SHA
  @state(Field) shaHashLow = State<Field>();         // Field 1: Low 128 bits of SHA
  @state(Field) creatorXHigh = State<Field>();       // Field 2: Creator public key X high
  @state(Field) creatorXLow = State<Field>();        // Field 3: Creator public key X low
  @state(Field) creatorYHigh = State<Field>();       // Field 4: Creator public key Y high
  @state(Field) creatorYLow = State<Field>();        // Field 5: Creator public key Y low

  /**
   * Just verify they can be read (not zero means initialized)
   */
  @method async assertValid() {
    const shaHashHigh = this.shaHashHigh.getAndRequireEquals();
    const shaHashLow = this.shaHashLow.getAndRequireEquals();
  }
}