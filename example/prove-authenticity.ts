import {
  AuthenticityProgram,
  AuthenticityInputs,
  FinalRoundInputs,
  prepareImageVerification,
  AuthenticityZkApp,
  SHACommitment,
  hashImageOffCircuit,
  computeOnChainCommitment,
  MintEvent,
  generateECKeyPair,
  Ecdsa,
  Secp256r1,
  Secp256r1Commitment,
} from '../src/index.js';
import { PrivateKey, Mina, AccountUpdate } from 'o1js';
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

// Step 9: Verify mint event was emitted correctly
console.log('9️⃣ Verifying mint event...');
const events = await zkApp.fetchEvents();
console.log(`   Found ${events.length} event(s)`);

if (events.length > 0) {
  const latestEvent = events[events.length - 1];
  const eventData = latestEvent.event.data as unknown as MintEvent;

  console.log('\n   Mint Event Data:');
  console.log(`   - Token Address: ${eventData.tokenAddress.toBase58()}`);

  // The creator is now stored as four individual fields, reconstruct to compare
  const eventCreatorCommitment = Secp256r1Commitment.fromFourFields(
    eventData.tokenCreatorXHigh,
    eventData.tokenCreatorXLow,
    eventData.tokenCreatorYHigh,
    eventData.tokenCreatorYLow
  );
  const eventCreatorKey = eventCreatorCommitment.toPublicKey();
  console.log(`   - Token Creator x: ${eventCreatorKey.x.toBigInt()}`);
  console.log(`   - Token Creator y: ${eventCreatorKey.y.toBigInt()}`);
  const eventShaCommitment = SHACommitment.fromTwoFields(
    eventData.authenticityCommitmentHigh,
    eventData.authenticityCommitmentLow
  );
  console.log(`   - Commitment: ${eventShaCommitment.toHex()}`);

  // Verify event data matches expected values
  console.log('\n   Mint Event Verification:');
  console.log(
    `   - Token address matches: ${eventData.tokenAddress
      .equals(tokenOwnerAccount)
      .toBoolean()}`
  );

  // Compare the reconstructed key with the original
  const keysMatch =
    eventCreatorKey.x.toBigInt() === creatorPublicKey.x.toBigInt() &&
    eventCreatorKey.y.toBigInt() === creatorPublicKey.y.toBigInt();
  console.log(`   - Creator public key matches: ${keysMatch}`);
  console.log(
    `   - Commitment matches: ${eventShaCommitment.toHex() === imageHash}`
  );
} else {
  console.log('   ❌ No events found!');
}

// Step 10: Verify the on-chain data
console.log('\n🔟 Verifying on-chain data...');

// Get the token ID
const tokenId = zkApp.deriveTokenId();
console.log(`🪙 Token ID: ${tokenId.toString()}`);

// Check the token account state
const tokenAccount = Mina.getAccount(tokenOwnerAccount, tokenId);
const storedHigh128 = tokenAccount.zkapp?.appState[1];
const storedLow128 = tokenAccount.zkapp?.appState[2];

// Reconstruct the SHA commitment from stored fields
const shaCommitment = new SHACommitment({
  bytes: verificationInputs.expectedHash,
});
const { high128: expectedHigh, low128: expectedLow } =
  shaCommitment.toTwoFields();

// Creator key is now stored as 4 fields instead of 6
const storedCreatorXHigh = tokenAccount.zkapp?.appState[3];
const storedCreatorXLow = tokenAccount.zkapp?.appState[4];
const storedCreatorYHigh = tokenAccount.zkapp?.appState[5];
const storedCreatorYLow = tokenAccount.zkapp?.appState[6];

// Reconstruct the creator commitment from stored fields
const expectedCreatorCommitment =
  Secp256r1Commitment.fromPublicKey(creatorPublicKey);
const { xHigh128, xLow128, yHigh128, yLow128 } =
  expectedCreatorCommitment.toFourFields();

console.log('\n📊 On-chain verification results:');
console.log(
  `   Stored high128 matches: ${
    storedHigh128?.toString() === expectedHigh.toString()
  }`
);
console.log(
  `   Stored low128 matches: ${
    storedLow128?.toString() === expectedLow.toString()
  }`
);
console.log(
  `   Creator public key xHigh matches: ${
    storedCreatorXHigh?.toString() === xHigh128.toString()
  }`
);
console.log(
  `   Creator public key xLow matches: ${
    storedCreatorXLow?.toString() === xLow128.toString()
  }`
);
console.log(
  `   Creator public key yHigh matches: ${
    storedCreatorYHigh?.toString() === yHigh128.toString()
  }`
);
console.log(
  `   Creator public key yLow matches: ${
    storedCreatorYLow?.toString() === yLow128.toString()
  }`
);

// Verify we can reconstruct the original hash
if (storedHigh128 && storedLow128) {
  const reconstructedCommitment = SHACommitment.fromTwoFields(
    storedHigh128,
    storedLow128
  );
  console.log('\n🔍 Reconstructed commitment verification:');
  console.log(`   Original SHA-256: ${imageHash}`);
  console.log(`   Reconstructed:    ${reconstructedCommitment.toHex()}`);
  console.log(`   Matches: ${reconstructedCommitment.toHex() === imageHash}`);
}

// Test the helper function with the new storage format
console.log('\n1️⃣1️⃣ Testing computeOnChainCommitment helper:');
const helperResult = await computeOnChainCommitment(imageData);

console.log(
  `   Low128 matches stored: ${
    helperResult.low128.toString() === storedLow128?.toString()
  }`
);
console.log(
  `   High128 matches stored: ${
    helperResult.high128.toString() === storedHigh128?.toString()
  }`
);

console.log('\n🎉 Example completed successfully!');
console.log('\nSummary:');
console.log(`- Image: ${imagePath} (${imageData.length} bytes)`);
console.log(`- SHA-256: ${imageHash}`);
console.log(`- Token minted to: ${tokenOwnerAccount.toBase58()}`);
console.log(`- Created by: ${creatorKey.toBigInt()}`);
