export {
  // Main zkProgram and proof types
  AuthenticityProgram,
  AuthenticityProof,
  AuthenticityInputs,
} from './AuthenticityProof.js';

export {
  // Helper classes and functions
  Bytes32,
  FinalRoundInputs,
  hashUntilFinalRound,
  performFinalSHA256Round,
  hashImageOffCircuit,
  prepareImageVerification,
  computeOnChainCommitment,
} from './commitmentHelpers.js';

export {
  // Smart contract
  AuthenticityZkApp,
} from './AuthenticityZkApp.js';