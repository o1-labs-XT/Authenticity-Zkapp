import {
  AuthenticityProgram,
  AuthenticityInputs,
  FinalRoundInputs,
  prepareImageVerification,
  AuthenticityZkApp,
  hashImageOffCircuit,
  computeOnChainCommitment,
  generateECKeyPair,
  Ecdsa,
  Secp256r1,
} from '../src/index.js';
import { PrivateKey, Signature, Mina, AccountUpdate, Poseidon } from 'o1js';
import fs from 'fs';

console.log('🐱 Authenticity zkApp Example\n');

// Step 1: Setup Local Blockchain
console.log('1️⃣ Setting up Local Blockchain...');
const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);

// Create test accounts
const deployerKey = Local.testAccounts[0].key;
const deployerAccount = deployerKey.toPublicKey();
const tokenOwnerKey = Local.testAccounts[2].key;
const tokenOwnerAccount = tokenOwnerKey.toPublicKey();
const payerKey = Local.testAccounts[3].key;
const payerAccount = payerKey.toPublicKey();
const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
const creatorPublicKey = Secp256r1.fromHex(publicKeyHex);
const creatorKey = Secp256r1.Scalar.from(privateKeyBigInt);
console.log('✅ Local blockchain ready\n');

// Step 2: Load the cat image
console.log('2️⃣ Loading cat image...');
const imagePath = './build/example/cat.png';
const imageData = fs.readFileSync(imagePath);
const imageHash = hashImageOffCircuit(imageData);
console.log(`📷 Image loaded: ${imagePath}`);
console.log(`#️⃣ SHA-256 hash: ${imageHash}\n`);

// Step 3: Compile the zkProgram
console.log('3️⃣ Compiling AuthenticityProgram...');
const programStartTime = Date.now();
await AuthenticityProgram.compile();
console.log(
  `✅ Program compiled in ${((Date.now() - programStartTime) / 1000).toFixed(
    1
  )}s\n`
);

const programSummary = await AuthenticityProgram.analyzeMethods();
console.log('Program Summary: ', programSummary.verifyAuthenticity.summary());

// Step 4: Prepare verification inputs
console.log('4️⃣ Preparing image verification inputs...');
const verificationInputs = prepareImageVerification(imagePath);

// Create signature to prove ownership

const signature = Ecdsa.signHash(
  verificationInputs.expectedHash,
  creatorKey.toBigInt()
);

// Create public and private inputs
const publicInputs = new AuthenticityInputs({
  commitment: verificationInputs.expectedHash,
  signature,
  publicKey: creatorPublicKey,
});

const privateInputs = new FinalRoundInputs({
  state: verificationInputs.penultimateState,
  initialState: verificationInputs.initialState,
  messageWord: verificationInputs.messageWord,
  roundConstant: verificationInputs.roundConstant,
});

console.log('✅ Inputs prepared\n');

// Step 5: Generate the proof
console.log('5️⃣ Generating authenticity proof...');
const proofStartTime = Date.now();
const { proof } = await AuthenticityProgram.verifyAuthenticity(
  publicInputs,
  privateInputs
);
console.log(
  `✅ Proof generated in ${((Date.now() - proofStartTime) / 1000).toFixed(
    1
  )}s\n`
);

// Step 6: Verify the proof
console.log('6️⃣ Verifying proof...');
const isValid = await AuthenticityProgram.verify(proof);
console.log(`✅ Proof is ${isValid ? 'VALID' : 'INVALID'}\n`);

// Step 7: Deploy the smart contract
console.log('7️⃣ Deploying AuthenticityZkApp contract...');
const zkAppKey = PrivateKey.random();
const zkApp = new AuthenticityZkApp(zkAppKey.toPublicKey());

// Compile the contract
console.log('   Compiling contract...');
const contractStartTime = Date.now();
await AuthenticityZkApp.compile();
console.log(
  `   Contract compiled in ${((Date.now() - contractStartTime) / 1000).toFixed(
    1
  )}s`
);

// Deploy transaction
const deployTxn = await Mina.transaction(deployerAccount, async () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  await zkApp.deploy();
});
await deployTxn.prove();
await deployTxn.sign([deployerKey, zkAppKey]).send();
console.log('✅ Contract deployed\n');

// Step 8: Verify and store image metadata on-chain
console.log('8️⃣ Storing image authenticity on-chain...');
const storeTxn = await Mina.transaction(payerAccount, async () => {
  // Fund the token account
  AccountUpdate.fundNewAccount(payerAccount);

  await zkApp.verifyAndStore(tokenOwnerAccount, proof, publicInputs);
});
await storeTxn.prove();
await storeTxn.sign([payerKey, tokenOwnerKey]).send();
console.log('✅ Image authenticity stored on-chain\n');

// Step 9: Verify the on-chain data
console.log('9️⃣ Verifying on-chain data...');

// Get the token ID
const tokenId = zkApp.deriveTokenId();
console.log(`🪙 Token ID: ${tokenId.toString()}`);

// Check the token account state
const tokenAccount = Mina.getAccount(tokenOwnerAccount, tokenId);
const storedCommitment = tokenAccount.zkapp?.appState[0];
const storedCreatorX1 = tokenAccount.zkapp?.appState[1];
const storedCreatorX2 = tokenAccount.zkapp?.appState[2];
const storedCreatorX3 = tokenAccount.zkapp?.appState[3];

const storedCreatorY1 = tokenAccount.zkapp?.appState[4];
const storedCreatorY2 = tokenAccount.zkapp?.appState[5];
const storedCreatorY3 = tokenAccount.zkapp?.appState[6];

console.log('\n📊 On-chain verification results:');
console.log(
  `   Stored commitment matches: ${
    storedCommitment?.toString() ===
    Poseidon.hash(verificationInputs.expectedHash.toFields()).toString()
  }`
);
console.log(
  `   Creator public key X1 matches: ${
    storedCreatorX1?.toString() === creatorPublicKey.x.toFields()[0].toString()
  }`
);
console.log(
  `   Creator public key X2 matches: ${
    storedCreatorX2?.toString() === creatorPublicKey.x.toFields()[1].toString()
  }`
);
console.log(
  `   Creator public key X3 matches: ${
    storedCreatorX3?.toString() === creatorPublicKey.x.toFields()[2].toString()
  }`
);
console.log(
  `   Creator public key Y1 matches: ${
    storedCreatorY1?.toString() === creatorPublicKey.y.toFields()[0].toString()
  }`
);
console.log(
  `   Creator public key Y2 matches: ${
    storedCreatorY2?.toString() === creatorPublicKey.y.toFields()[1].toString()
  }`
);
console.log(
  `   Creator public key Y3 matches: ${
    storedCreatorY3?.toString() === creatorPublicKey.y.toFields()[2].toString()
  }`
);

// Test the new helper function
console.log('\n🧪 Testing computeOnChainCommitment helper:');
const helperCommitment = computeOnChainCommitment(imageData);
console.log(`   Helper result: ${helperCommitment.poseidon.toString()}`);
console.log(`   Stored value:  ${storedCommitment?.toString()}`);
console.log(
  `   Helper matches stored value: ${
    helperCommitment.poseidon.toString() === storedCommitment?.toString()
  }`
);

console.log('\n🎉 Example completed successfully!');
console.log('\nSummary:');
console.log(`- Image: ${imagePath} (${imageData.length} bytes)`);
console.log(`- SHA-256: ${imageHash}`);
console.log(`- Token minted to: ${tokenOwnerAccount.toBase58()}`);
console.log(`- Created by: ${creatorKey.toBigInt()}`);
