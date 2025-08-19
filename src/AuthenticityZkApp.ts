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

import { AuthenticityProof, AuthenticityInputs } from './AuthenticityProof.js';

export { MintEvent, AuthenticityZkApp };
/**
 * Event emitted when a new authenticity token is minted
 */
class MintEvent extends Struct({
  tokenAddress: PublicKey,
  tokenCreator: PublicKey,
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
      value: creator.x,
    };
    update.body.update.appState[2] = {
      isSome: Bool(true),
      value: creator.isOdd.toField(),
    };
  }
}
