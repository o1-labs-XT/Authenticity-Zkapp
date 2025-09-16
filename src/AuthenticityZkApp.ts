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
  Reducer,
  SmartContract,
} from 'o1js';

import { AuthenticityProof } from './AuthenticityProof.js';

import {
  SHACommitment,
  Secp256r1Commitment,
  Bytes32,
  PackedImageChainCounters
} from './helpers/index.js';


export { AuthenticityZkApp, ImageMintAction };

// Action dispatched when a new authenticity token is minted
class ImageMintAction extends Struct({
  tokenAddress: PublicKey,             // Token mint address
  chainId: UInt8,                      // Chain ID (0-24)
  imageCount: Field,                   // New count for this chain after mint
  tokenCreatorXHigh: Field,            // Creator public key X coordinate high 128 bits
  tokenCreatorXLow: Field,             // Creator public key X coordinate low 128 bits
  tokenCreatorYHigh: Field,            // Creator public key Y coordinate high 128 bits
  tokenCreatorYLow: Field,             // Creator public key Y coordinate low 128 bits
  authenticityCommitmentHigh: Field,   // SHA commitment high 128 bits
  authenticityCommitmentLow: Field,    // SHA commitment low 128 bits
}) { }

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

  reducer = Reducer({ actionType: ImageMintAction });

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

    // Dispatch action with compressed fields and chain information
    this.reducer.dispatch(new ImageMintAction({
      tokenAddress: address,
      chainId,
      imageCount: newCount.value,
      tokenCreatorXHigh: xHigh128,
      tokenCreatorXLow: xLow128,
      tokenCreatorYHigh: yHigh128,
      tokenCreatorYLow: yLow128,
      authenticityCommitmentHigh: shaHigh,
      authenticityCommitmentLow: shaLow,
    }));

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
