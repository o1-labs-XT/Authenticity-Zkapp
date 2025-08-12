# Mina zkApp: Authenticity Zkapp

A zero-knowledge proof system for verifying image authenticity on the Mina blockchain.

## Installation

```sh
npm install authenticity-zkapp
```

## Usage

### Run the Example Script

```sh
npm run example
```

### Basic Image Verification

```typescript
import {
  AuthenticityProgram,
  AuthenticityInputs,
  FinalRoundInputs,
  prepareImageVerification,
  Bytes32
} from 'authenticity-zkapp';
import { PrivateKey, PublicKey, Signature } from 'o1js';

// 1. Compile the zkProgram
await AuthenticityProgram.compile();

// 2. Prepare image for verification
const verificationInputs = prepareImageVerification('path/to/image.jpg');

// 3. Create a signature to prove ownership
const privateKey = PrivateKey.random();
const publicKey = PublicKey.fromPrivateKey(privateKey);
const signature = Signature.create(
  privateKey, 
  verificationInputs.expectedHash.toFields()
);

// 4. Create public and private inputs
const publicInputs = new AuthenticityInputs({
  commitment: verificationInputs.expectedHash,
  signature,
  publicKey
});

const privateInputs = new FinalRoundInputs({
  state: verificationInputs.penultimateState,
  initialState: verificationInputs.initialState,
  messageWord: verificationInputs.messageWord,
  roundConstant: verificationInputs.roundConstant
});

// 5. Generate the proof
const { proof } = await AuthenticityProgram.verifyAuthenticity(
  publicInputs,
  privateInputs
);

// 6. Verify the proof
const isValid = await AuthenticityProgram.verify(proof);
console.log('Proof is valid:', isValid);
```

### Computing On-Chain Commitment

To compute the exact commitment value that will be stored on-chain:

```typescript
import { computeOnChainCommitment } from 'authenticity-zkapp';
import fs from 'fs';

const imageData = fs.readFileSync('path/to/image.jpg');
const commitment = computeOnChainCommitment(imageData);
console.log('On-chain commitment:', commitment.toString());
```

## API Reference

### Core Classes

- **`AuthenticityProgram`**: The main zkProgram for generating and verifying proofs
- **`AuthenticityProof`**: The proof type returned by the program
- **`AuthenticityInputs`**: Public inputs (commitment, signature, publicKey)
- **`FinalRoundInputs`**: Private inputs for SHA-256 final round verification
- **`Bytes32`**: 32-byte type for SHA-256 hashes
- **`AuthenticityZkApp`**: Smart contract for on-chain verification (stores Poseidon hash of commitment)

### Helper Functions

- **`prepareImageVerification(imagePath)`**: Prepares all inputs needed for proof generation
- **`hashImageOffCircuit(imageData)`**: Computes complete SHA-256 hash
- **`hashUntilFinalRound(imageData)`**: Computes SHA-256 up to the final round
- **`performFinalSHA256Round(...)`**: Executes final SHA-256 round in-circuit
- **`computeOnChainCommitment(imageData)`**: Computes the exact commitment value stored on-chain (SHA-256 → Poseidon)

## How It Works

This zkApp optimizes proof generation by splitting SHA-256 computation:
1. **Off-circuit**: Computes rounds 0-62 of SHA-256 in JavaScript
2. **In-circuit**: Only verifies the final round (63) using zkSNARKs

## Circuit Analysis

The AuthenticityProgram method `verifyAuthenticity` has the following summary:

```ts
{
  'Total rows': 908,
  Generic: 169,
  EndoMulScalar: 218,
  Rot64: 6,
  RangeCheck0: 18,
  Xor16: 36,
  Zero: 147,
  RangeCheck1: 6,
  ForeignFieldAdd: 3,
  Poseidon: 198,
  CompleteAdd: 5,
  VarBaseMul: 102
}
```

## Development

### Build

```sh
npm run build
```

### Run Tests

```sh
npm run test
```

### Lint & Format

```sh
npm run lint
npm run format
```

## Requirements

- Node.js >= 18.14.0
- o1js >= 2.0.0

## License

[Apache-2.0](LICENSE)
