import {
  PublicKey,
  method,
  TokenContract,
  UInt64,
  AccountUpdate,
  AccountUpdateForest,
  Bool,
  Poseidon,
} from 'o1js';

import { AuthenticityProof, AuthenticityInputs } from './AuthenticityProof.js';

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
