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
  // Cross-platform versions for browser compatibility
  hashImageOffCircuitCrossPlatform,
  computeOnChainCommitmentCrossPlatform,
} from './browser.js';

export {
  // Smart contract and types
  AuthenticityZkApp,
  SHACommitment,
} from './AuthenticityZkApp.js';
