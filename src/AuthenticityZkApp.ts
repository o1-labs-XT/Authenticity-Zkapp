import {
  PublicKey,
  method,
  TokenContract,
  UInt64,
  AccountUpdateForest,
  Bool,
  Field,
  Struct,
  state,
  State,
  VerificationKey,
  Permissions,
} from 'o1js';
import { AuthenticityProof } from './AuthenticityProof.js';

import {
  SHACommitment,
  Secp256r1Commitment,
  Bytes32
} from './helpers/index.js';

export { MintEvent, AuthenticityZkApp };

/**
 * Event emitted when a new authenticity token is minted
 */
class MintEvent extends Struct({
  tokenAddress: PublicKey,
  tokenId: Field,
  tokenCreatorXHigh: Field,
  tokenCreatorXLow: Field,
  tokenCreatorYHigh: Field,
  tokenCreatorYLow: Field,
  authenticityCommitmentHigh: Field, // High 128 bits of SHA
  authenticityCommitmentLow: Field, // Low 128 bits of SHA
}) { }

/**
 * Acts as a factory for TokenAccountContracts.
 * This contract:
 * - Verifies authenticity proofs
 * - Deploys new TokenAccountContract instances
 * - Mints tokens to those contracts
 */
class AuthenticityZkApp extends TokenContract {
  @state(Field) tokenAccountVkHash = State<Field>();
  @state(PublicKey) admin = State<PublicKey>();

  events = {
    mint: MintEvent,
  };

  init() {
    super.init();

    const deployer = this.sender.getAndRequireSignature();
    this.admin.set(deployer);
    // TokenAccountContract VK hash
    this.tokenAccountVkHash.set(Field.from('2500344745592430268173091005144987605594334572818740634112428059802822161761'));
  }


  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async approveBase(forest: AccountUpdateForest) {
    throw Error(
      'transfers of tokens are not allowed, change the owner instead'
    );
  }


  @method async verifyAndStore(proof: AuthenticityProof, tokenAccountVk: VerificationKey, tokenAccountAddress: PublicKey) {
    // Verify the provided proof using the AuthenticityProgram
    proof.verify();

    // Mint token to backend-generated address
    const tokenUpdate = this.internal.mint({
      address: tokenAccountAddress,
      amount: UInt64.from(1),
    });

    tokenUpdate.account.isNew.getAndRequireEquals().assertTrue();

    tokenUpdate.requireSignature();

    tokenAccountVk.hash.assertEquals(this.tokenAccountVkHash.getAndRequireEquals());

    tokenUpdate.body.update.verificationKey = {
      isSome: Bool(true),
      value: tokenAccountVk,
    };

    tokenUpdate.body.update.permissions = {
      isSome: Bool(true),
      value: {
        ...Permissions.default(),
        editState: Permissions.proof(),
        setVerificationKey: Permissions.VerificationKey.impossibleDuringCurrentVersion(),
        send: Permissions.impossible(), // soulbound
      },
    };

    // Create SHA commitment for the asset
    const shaCommitment = new SHACommitment({
      bytes: new Bytes32(proof.publicInput.commitment.bytes),
    });
    const { high128: shaHigh, low128: shaLow } = shaCommitment.toTwoFields();

    // Create compressed commitment for the creator's public key (signer)
    const creatorCommitment = Secp256r1Commitment.fromPublicKey(proof.publicInput.publicKey);
    const { xHigh128, xLow128, yHigh128, yLow128 } = creatorCommitment.toFourFields();

    // Set initial state directly on the token account
    tokenUpdate.body.update.appState = [
      { isSome: Bool(true), value: shaHigh },      // Field 0: SHA hash high
      { isSome: Bool(true), value: shaLow },       // Field 1: SHA hash low
      { isSome: Bool(true), value: xHigh128 },     // Field 2: Creator pubkey X high
      { isSome: Bool(true), value: xLow128 },      // Field 3: Creator pubkey X low
      { isSome: Bool(true), value: yHigh128 },     // Field 4: Creator pubkey Y high
      { isSome: Bool(true), value: yLow128 },      // Field 5: Creator pubkey Y low
      { isSome: Bool(true), value: Field(0) },     // Field 6: Empty
      { isSome: Bool(true), value: Field(0) },     // Field 7: Empty
    ];

    // Emit mint event with token address and ID
    this.emitEvent('mint', {
      tokenAddress: tokenAccountAddress,
      tokenId: tokenUpdate.tokenId,
      tokenCreatorXHigh: xHigh128,
      tokenCreatorXLow: xLow128,
      tokenCreatorYHigh: yHigh128,
      tokenCreatorYLow: yLow128,
      authenticityCommitmentHigh: shaHigh,
      authenticityCommitmentLow: shaLow,
    } as MintEvent);
  }
}
