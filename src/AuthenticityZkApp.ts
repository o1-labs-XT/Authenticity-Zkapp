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
} from 'o1js';
import { AuthenticityProof } from './AuthenticityProof.js';
import { TokenAccountContract } from './TokenAccountContract.js';

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
 * - Mints tokens to deployed TokenAccount Contracts  
 * - Sets initial state directly via account updates
 */
class AuthenticityZkApp extends TokenContract {
  @state(PublicKey) admin = State<PublicKey>();

  events = {
    mint: MintEvent,
  };

  init() {
    super.init();

    const deployer = this.sender.getAndRequireSignature();
    this.admin.set(deployer);
  }

  async approveBase(forest: AccountUpdateForest) {
    throw Error(
      'transfers of tokens are not allowed, change the owner instead'
    );
  }

  @method async verifyAndStore(proof: AuthenticityProof, tokenAccountAddress: PublicKey) {
    // Verify the provided proof using the AuthenticityProgram
    proof.verify();

    // Mint token to the deployed token account
    const tokenUpdate = this.internal.mint({
      address: tokenAccountAddress,
      amount: UInt64.from(1),
    });

    tokenUpdate.requireSignature();

    // Create SHA commitment for the asset
    const shaCommitment = new SHACommitment({
      bytes: new Bytes32(proof.publicInput.commitment.bytes),
    });
    const { high128: shaHigh, low128: shaLow } = shaCommitment.toTwoFields();

    // Create compressed commitment for the creator's public key (signer)
    const creatorCommitment = Secp256r1Commitment.fromPublicKey(proof.publicInput.publicKey);
    const { xHigh128, xLow128, yHigh128, yLow128 } = creatorCommitment.toFourFields();

    const tokenId = this.deriveTokenId();
    const tokenContract = new TokenAccountContract(tokenAccountAddress, tokenId);
    await tokenContract.setAuthenticityData(
      shaHigh,
      shaLow,
      xHigh128,
      xLow128,
      yHigh128,
      yLow128
    );

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
