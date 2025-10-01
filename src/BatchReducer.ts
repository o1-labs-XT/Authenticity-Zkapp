import {
  Experimental,
  Field,
  UInt8,
  UInt32,
  Bool,
  Provable,
  PublicKey,
  Struct,
} from 'o1js';
import { PackedImageChainCounters } from './helpers/index.js';

// Action dispatched when a new authenticity token is minted
export class ImageMintAction extends Struct({
  tokenAddress: PublicKey,             // Token mint address
  chainId: UInt8,                      // Chain ID (0-24)
  tokenCreatorXHigh: Field,            // Creator public key X coordinate high 128 bits
  tokenCreatorXLow: Field,             // Creator public key X coordinate low 128 bits
  tokenCreatorYHigh: Field,            // Creator public key Y coordinate high 128 bits
  tokenCreatorYLow: Field,             // Creator public key Y coordinate low 128 bits
  authenticityCommitmentHigh: Field,   // SHA commitment high 128 bits
  authenticityCommitmentLow: Field,    // SHA commitment low 128 bits
}) { }


// BatchReducer instance for processing ImageMintActions
export const chainBatchReducer = new Experimental.BatchReducer({
  actionType: ImageMintAction,
  batchSize: 5,
  maxUpdatesFinalProof: 10,   // Max actions processed in zkApp method
  maxUpdatesPerProof: 20,     // Max actions per recursive proof chunk
});

export class ChainBatch extends chainBatchReducer.Batch { }
export class ChainBatchProof extends chainBatchReducer.BatchProof { }

// Helper functions for the contract integration
export class BatchReducerUtils {
  static processActionsInCircuit(
    batch: ChainBatch,
    proof: ChainBatchProof,
    initialCounters: Field
  ): Field {
    let counters = initialCounters;
    chainBatchReducer.processBatch({ batch, proof }, (action: ImageMintAction, isDummy: Bool) => {
      let updatedCounters = PackedImageChainCounters.incrementChain(counters, action.chainId);
      counters = Provable.if(
        isDummy,
        counters,           // Keep current if dummy
        updatedCounters     // Update if real action
      );
    });

    return counters;
  }

  // Compute winner from final chain counters (outside of batch processing)
  static computeWinner(chainCounters: Field): {
    winnerChainId: UInt8;
    winnerLength: UInt32;
  } {
    const { longestChainId, longestChainLength } = PackedImageChainCounters.findLongestChain(chainCounters);
    return {
      winnerChainId: longestChainId,
      winnerLength: longestChainLength,
    };
  }

  // Prepare batches with retry logic
  static async prepareBatches(retries = 3): Promise<
    { batch: ChainBatch; proof: ChainBatchProof }[]
  > {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const batches = await chainBatchReducer.prepareBatches();
        console.log(`Prepared ${batches.length} batches`);
        return batches;
      } catch (error) {
        console.log(`Batch preparation attempt ${attempt + 1}/${retries} failed:`, error);

        if (attempt === retries - 1) {
          throw new Error(`Failed to prepare batches after ${retries} attempts: ${error}`);
        }
        await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
      }
    }

    return []; // Should never reach here due to throw above
  }

  static dispatchAction(action: ImageMintAction): void {
    chainBatchReducer.dispatch(action);
  }

  static setContractInstance(contract: any): void { // We use any for contract type because BatchReducer expects a specific interface
    chainBatchReducer.setContractInstance(contract);
  }

  static async compile(): Promise<any> {
    console.log('Compiling BatchReducer program...');
    const result = await chainBatchReducer.compile();
    console.log('BatchReducer compiled successfully');
    return result;
  }
}