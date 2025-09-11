export {
  // Main zkProgram and proof types
  AuthenticityProgram,
  AuthenticityProof,
  AuthenticityInputs,
  Secp256r1,
  Ecdsa,
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
  generateECKeyPair,
  SHACommitment,
  Secp256r1Commitment,
  PackedImageChainCounters
} from './helpers/index.js';

export {
  // Cross-platform versions for browser compatibility
  hashImageOffCircuitCrossPlatform,
  computeOnChainCommitmentCrossPlatform,
} from './browser.js';

export {
  // Smart contract and types
  AuthenticityZkApp,
  MintEvent,
} from './AuthenticityZkApp.js';