import {
  SmartContract,
  state,
  State,
  Field,
  method,
  Permissions,
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

  init() {
    super.init();

    this.account.permissions.set({
      ...Permissions.default(),
      editState: Permissions.proof(), // Allow factory to update state
      send: Permissions.impossible(), // Soulbound
      setVerificationKey: Permissions.VerificationKey.impossibleDuringCurrentVersion(),
    });
  }


  @method async setAuthenticityData(
    shaHashHigh: Field,
    shaHashLow: Field,
    creatorXHigh: Field,
    creatorXLow: Field,
    creatorYHigh: Field,
    creatorYLow: Field
  ) {
    // this.shaHashHigh.getAndRequireEquals().assertEquals(Field(0));
    // this.shaHashLow.getAndRequireEquals().assertEquals(Field(0));
    // this.creatorXHigh.getAndRequireEquals().assertEquals(Field(0));
    // this.creatorXLow.getAndRequireEquals().assertEquals(Field(0));
    // this.creatorYHigh.getAndRequireEquals().assertEquals(Field(0));
    // this.creatorYLow.getAndRequireEquals().assertEquals(Field(0));

    this.shaHashHigh.set(shaHashHigh);
    this.shaHashLow.set(shaHashLow);
    this.creatorXHigh.set(creatorXHigh);
    this.creatorXLow.set(creatorXLow);
    this.creatorYHigh.set(creatorYHigh);
    this.creatorYLow.set(creatorYLow);
  }
}