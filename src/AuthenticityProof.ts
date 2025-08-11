import { Field, Struct, ZkProgram } from 'o1js';
export { AuthenticityProgram, AuthenticityProof, AuthenticityInputs };

class AuthenticityInputs extends Struct({
  committment: Field,
}) {}

const AuthenticityProgram = ZkProgram({
  name: 'AuthenticityProgram',
  publicInput: AuthenticityInputs,
  methods: {
    verifyAuthenticity: {
      privateInputs: [],
      method: async (publicInput: AuthenticityInputs) => {
        // TODO
      },
    },
  },
});

class AuthenticityProof extends ZkProgram.Proof(AuthenticityProgram) {}
