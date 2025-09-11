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
  State,
  state,
  UInt8,
} from 'o1js';

import { AuthenticityProof } from './AuthenticityProof.js';

import {
  SHACommitment,
  Secp256r1Commitment,
  Bytes32,
  PackedImageChainCounters
} from './helpers/index.js';


export { MintEvent, AuthenticityZkApp };

/**
 * Event emitted when a new authenticity token is minted
 */
class MintEvent extends Struct({
  tokenAddress: PublicKey,
  chainId: UInt8, // Chain this image belongs to
  imageCount: Field, // New count for this chain
  tokenCreatorXHigh: Field,
  tokenCreatorXLow: Field,
  tokenCreatorYHigh: Field,
  tokenCreatorYLow: Field,
  authenticityCommitmentHigh: Field, // High 128 bits of SHA
  authenticityCommitmentLow: Field, // Low 128 bits of SHA
}) {}

/**
 * ZkApp that verifies authenticity proofs and stores metadata on-chain.
 *
 * Metadata to store:
 *  - Hash/commitment of the digital asset
 *  - Creator's public key
 */
class AuthenticityZkApp extends TokenContract {
  // State for packed chain counters (25 chains × 10 bits each)
  @state(Field) chainCounters = State<Field>();

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
    chainId: UInt8, // Chain ID (0-24)
    proof: AuthenticityProof,
  ) {
    chainId.assertLessThanOrEqual(UInt8.from(PackedImageChainCounters.CHAIN_COUNT - 1), 'Invalid chain ID, it must be 0-24');

    // Verify the provided proof using the AuthenticityProgram
    proof.verify();
    const currentCounters = this.chainCounters.getAndRequireEquals();

    const isFull = PackedImageChainCounters.isChainFull(currentCounters, chainId);
    isFull.assertFalse('Chain has reached maximum capacity (1023 images)');
    
    const updatedCounters = PackedImageChainCounters.incrementChain(currentCounters, chainId);
    this.chainCounters.set(updatedCounters);

    const newCount = PackedImageChainCounters.getChainLength(updatedCounters, chainId);

    // Mint a token with the image metadata
    const tokenId = this.deriveTokenId();
    const update = AccountUpdate.createSigned(address, tokenId);
    update.account.isNew.getAndRequireEquals().assertTrue();

    this.internal.mint({
      address,
      amount: UInt64.from(1),
    });

    // Create SHA commitment for the asset
    const shaCommitment = new SHACommitment({
      bytes: new Bytes32(proof.publicInput.commitment.bytes),
    });
    const { high128: shaHigh, low128: shaLow } = shaCommitment.toTwoFields();

    // Create compressed commitment for the creator's public key
    const creatorCommitment = Secp256r1Commitment.fromPublicKey(proof.publicInput.publicKey);
    const { xHigh128, xLow128, yHigh128, yLow128 } =
      creatorCommitment.toFourFields();

    // Emit event with compressed fields and chain information
    this.emitEvent('mint', {
      tokenAddress: address,
      chainId,
      imageCount: newCount.value,
      tokenCreatorXHigh: xHigh128,
      tokenCreatorXLow: xLow128,
      tokenCreatorYHigh: yHigh128,
      tokenCreatorYLow: yLow128,
      authenticityCommitmentHigh: shaHigh,
      authenticityCommitmentLow: shaLow,
    } as MintEvent);

    // Set the on-chain state of the token account
    update.body.update.appState[0] = {
      isSome: Bool(true),
      value: Field(2), // Token Schema Version 2 (using compression)
    };
    update.body.update.appState[1] = {
      isSome: Bool(true),
      value: shaHigh, // High 128 bits of the SHA commitment
    };
    update.body.update.appState[2] = {
      isSome: Bool(true),
      value: shaLow, // Low 128 bits of the SHA commitment
    };
    update.body.update.appState[3] = {
      isSome: Bool(true),
      value: xHigh128, // Creator's public key x high 128 bits
    };
    update.body.update.appState[4] = {
      isSome: Bool(true),
      value: xLow128, // Creator's public key x low 128 bits
    };
    update.body.update.appState[5] = {
      isSome: Bool(true),
      value: yHigh128, // Creator's public key y high 128 bits
    };
    update.body.update.appState[6] = {
      isSome: Bool(true),
      value: yLow128, // Creator's public key y low 128 bits
    };
  }
}
