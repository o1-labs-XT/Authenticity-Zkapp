import {
  PublicKey,
  method,
  TokenContract,
  UInt64,
  AccountUpdate,
  AccountUpdateForest,
  Bool,
  Poseidon,
  Struct,
  Field,
} from 'o1js';

import {
  AuthenticityProof,
  AuthenticityInputs,
  Secp256r1,
} from './AuthenticityProof.js';

export { MintEvent, AuthenticityZkApp };
/**
 * Event emitted when a new authenticity token is minted
 */
class MintEvent extends Struct({
  tokenAddress: PublicKey,
  tokenCreator: Secp256r1,
  authenticityCommitment: Field,
}) {}

/**
 * ZkApp that verifies authenticity proofs and stores metadata on-chain.
 *
 * Metadata to store:
 *  - Hash/commitment of the digital asset
 *  - Creator's public key
 */
class AuthenticityZkApp extends TokenContract {
  events = {
    mint: MintEvent,
  };

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
    inputs.publicKey.x.assertEquals(creator.x);
    inputs.publicKey.y.assertEquals(creator.y);
    inputs.signature.r.assertEquals(proof.publicInput.signature.r);
    inputs.signature.s.assertEquals(proof.publicInput.signature.s);
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

    this.emitEvent('mint', {
      tokenAddress: address,
      tokenCreator: creator,
      authenticityCommitment: Poseidon.hash(inputs.commitment.toFields()),
    } as MintEvent);

    // Set the on-chain state of the token account
    update.body.update.appState[0] = {
      isSome: Bool(true),
      value: Poseidon.hash(inputs.commitment.toFields()),
    };
    update.body.update.appState[1] = {
      isSome: Bool(true),
      value: creator.x.toFields()[0],
    };
    update.body.update.appState[2] = {
      isSome: Bool(true),
      value: creator.x.toFields()[1],
    };
    update.body.update.appState[3] = {
      isSome: Bool(true),
      value: creator.x.toFields()[2],
    };
    update.body.update.appState[4] = {
      isSome: Bool(true),
      value: creator.y.toFields()[0],
    };
    update.body.update.appState[5] = {
      isSome: Bool(true),
      value: creator.y.toFields()[1],
    };
    update.body.update.appState[6] = {
      isSome: Bool(true),
      value: creator.y.toFields()[2],
    };
  }
}
