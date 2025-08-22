import {
  UInt8,
  Struct,
  ZkProgram,
  Provable,
  createForeignCurve,
  createEcdsa,
  Crypto,
} from 'o1js';
import {
  Bytes32,
  FinalRoundInputs,
  performFinalSHA256Round,
} from './commitmentHelpers.js';
export {
  AuthenticityProgram,
  AuthenticityProof,
  AuthenticityInputs,
  Secp256r1,
  Ecdsa,
};

class Secp256r1 extends createForeignCurve(Crypto.CurveParams.Secp256r1) {}
class Ecdsa extends createEcdsa(Secp256r1) {}

class AuthenticityInputs extends Struct({
  commitment: Bytes32,
  signature: Ecdsa,
  publicKey: Secp256r1,
}) {}

const AuthenticityProgram = ZkProgram({
  name: 'AuthenticityProgram',
  publicInput: AuthenticityInputs,
  methods: {
    verifyAuthenticity: {
      privateInputs: [FinalRoundInputs],
      method: async (
        publicInput: AuthenticityInputs,
        roundInputs: FinalRoundInputs
      ) => {
        // Compute the final round of SHA-256 hashing
        const finalHash = performFinalSHA256Round(
          [
            roundInputs.state[0],
            roundInputs.state[1],
            roundInputs.state[2],
            roundInputs.state[3],
            roundInputs.state[4],
            roundInputs.state[5],
            roundInputs.state[6],
            roundInputs.state[7],
          ],
          [
            roundInputs.initialState[0],
            roundInputs.initialState[1],
            roundInputs.initialState[2],
            roundInputs.initialState[3],
            roundInputs.initialState[4],
            roundInputs.initialState[5],
            roundInputs.initialState[6],
            roundInputs.initialState[7],
          ],
          roundInputs.messageWord,
          roundInputs.roundConstant
        );

        // Convert UInt32 array to Bytes32 for comparison
        // Each UInt32 is 4 bytes, so we need to convert 8 UInt32s to 32 bytes
        const hashBytes: UInt8[] = [];
        for (let i = 0; i < 8; i++) {
          // Convert each UInt32 to 4 bytes (big-endian)
          const bytes = finalHash[i].toBytesBE();
          hashBytes.push(...bytes);
        }

        // Create Bytes32 from the array of UInt8s
        const computedHash = Bytes32.from(hashBytes);

        // Verify the computed hash matches the commitment
        Provable.assertEqual(computedHash, publicInput.commitment);

        // Verify the signature against the commitment
        publicInput.signature
          .verifySignedHash(publicInput.commitment, publicInput.publicKey)
          .assertTrue();
      },
    },
  },
});

class AuthenticityProof extends ZkProgram.Proof(AuthenticityProgram) {}
