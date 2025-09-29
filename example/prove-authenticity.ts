import {
  AuthenticityProgram,
  AuthenticityInputs,
  FinalRoundInputs,
  prepareImageVerification,
  AuthenticityZkApp,
  PackedImageChainCounters,
  SHACommitment,
  hashImageOffCircuit,
  computeOnChainCommitment,
  generateECKeyPair,
  Ecdsa,
  Secp256r1,
  Secp256r1Commitment,
  BatchReducerUtils,
} from '../src/index.js';
import { PrivateKey, Mina, AccountUpdate, UInt8, Field } from 'o1js';
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

// Set contract instance before any compilation
BatchReducerUtils.setContractInstance(zkApp);

// Compile dependencies first
console.log('   Compiling BatchReducer...');
const reducerCompileStart = Date.now();
await BatchReducerUtils.compile();
console.log(
  `   BatchReducer compiled in ${((Date.now() - reducerCompileStart) / 1000).toFixed(1)}s`
);

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
console.log('Contract deployed with initialized chain counters\n');

// Set up BatchReducer contract instance
console.log('🔧 Setting up BatchReducer with contract instance...');
BatchReducerUtils.setContractInstance(zkApp);
console.log('BatchReducer configured successfully\n');

// Step 8: Verify and store image metadata on-chain
console.log('8️⃣ Storing image authenticity on-chain with multiple image chains...');

// Show initial chain state
console.log('\n   📊 Initial Chain State:');
const initialTotalCount = PackedImageChainCounters.getTotalImageCount(zkApp.chainCounters.getAndRequireEquals());
console.log(`   Total images across all chains: ${Number(initialTotalCount.toBigint())}`);

// Create additional unique token owners for each mint
const tokenOwner2Key = Local.testAccounts[4].key;
const tokenOwner2Account = tokenOwner2Key.toPublicKey();
const tokenOwner3Key = Local.testAccounts[5].key;
const tokenOwner3Account = tokenOwner3Key.toPublicKey();
const tokenOwner4Key = Local.testAccounts[6].key;
const tokenOwner4Account = tokenOwner4Key.toPublicKey();
const tokenOwner5Key = Local.testAccounts[7].key;
const tokenOwner5Account = tokenOwner5Key.toPublicKey();
const tokenOwner6Key = Local.testAccounts[8].key;
const tokenOwner6Account = tokenOwner6Key.toPublicKey();
const tokenOwner7Key = Local.testAccounts[9].key;
const tokenOwner7Account = tokenOwner7Key.toPublicKey();

// Mint 4 images to Chain 0
console.log('\n   🏆 Minting 4 images to Chain 0...');
const chain0Txn1 = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwnerAccount, UInt8.from(0), proof);
});
await chain0Txn1.prove();
await chain0Txn1.sign([payerKey, tokenOwnerKey]).send();

const chain0Txn2 = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner2Account, UInt8.from(0), proof);
});
await chain0Txn2.prove();
await chain0Txn2.sign([payerKey, tokenOwner2Key]).send();

const chain0Txn3 = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner3Account, UInt8.from(0), proof);
});
await chain0Txn3.prove();
await chain0Txn3.sign([payerKey, tokenOwner3Key]).send();

const chain0Txn4 = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner4Account, UInt8.from(0), proof);
});
await chain0Txn4.prove();
await chain0Txn4.sign([payerKey, tokenOwner4Key]).send();

// Mint 2 images to Chain 5
console.log('   ☕ Minting 2 images to Chain 5...');
const chain5Txn1 = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner5Account, UInt8.from(5), proof);
});
await chain5Txn1.prove();
await chain5Txn1.sign([payerKey, tokenOwner5Key]).send();

const chain5Txn2 = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner6Account, UInt8.from(5), proof);
});
await chain5Txn2.prove();
await chain5Txn2.sign([payerKey, tokenOwner6Key]).send();

// Mint 1 image to Chain 24 (test full range)
console.log('   🔚 Minting 1 image to Chain 24...');
const chain24Txn = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner7Account, UInt8.from(24), proof);
});
await chain24Txn.prove();
await chain24Txn.sign([payerKey, tokenOwner7Key]).send();

console.log('✅ All chain mints completed!\n');

// Step 9: Process actions with BatchReducer
console.log('9️⃣ Processing actions with BatchReducer...');

// Prepare batches from pending actions
console.log('   Preparing batches from pending actions...');
const batches = await BatchReducerUtils.prepareBatches();

if (batches.length === 0) {
  console.log('   No pending actions to process');
} else {
  console.log(`   Found ${batches.length} batch(es) to process`);

  // Process each batch
  for (let i = 0; i < batches.length; i++) {
    console.log(`   Processing batch ${i + 1}/${batches.length}...`);

    const { batch, proof } = batches[i];

    // Create transaction to process this batch
    const batchTxn = await Mina.transaction(deployerAccount, async () => {
      await zkApp.processBatch(batch, proof);
    });

    console.log(`   Proving batch ${i + 1}...`);
    await batchTxn.prove();
    await batchTxn.sign([deployerKey]).send();

    console.log(`   Batch ${i + 1} processed successfully`);
  }
}

console.log('\nAll batches processed successfully!\n');

// Get final state from contract
const finalChainCounters = zkApp.chainCounters.getAndRequireEquals();
const winnerChainId = zkApp.currentWinner.getAndRequireEquals();
const winnerLength = zkApp.winnerLength.getAndRequireEquals();

// Display chain counter data after batch processing
console.log('Chain Counter Data (After Batch Processing):');
const finalTotalCount = PackedImageChainCounters.getTotalImageCount(finalChainCounters);
const chain0Count = PackedImageChainCounters.getChainLength(finalChainCounters, UInt8.from(0));
const chain5Count = PackedImageChainCounters.getChainLength(finalChainCounters, UInt8.from(5));
const chain24Count = PackedImageChainCounters.getChainLength(finalChainCounters, UInt8.from(24));
const chain2Count = PackedImageChainCounters.getChainLength(finalChainCounters, UInt8.from(2)); // Should be 0

console.log(`   Total images across all chains: ${Number(finalTotalCount.toBigint())}`);
console.log(`   Chain 0 count: ${Number(chain0Count.toBigint())}`);
console.log(`   Chain 5 count: ${Number(chain5Count.toBigint())}`);
console.log(`   Chain 24 count: ${Number(chain24Count.toBigint())}`);
console.log(`   Chain 2 count (unused): ${Number(chain2Count.toBigint())}`);

// Get winner from contract state (computed in-circuit during batch processing)
console.log('\n🏆 Winner determined by BatchReducer in-circuit...');
const longestChainId = Number(winnerChainId.toBigInt());
const longestChainLength = Number(winnerLength.toBigint());

console.log(`   Longest chain: Chain ${longestChainId} with ${longestChainLength} images`);
console.log(`   Winner determined: Chain ${longestChainId}`);

console.log('\n📋 Final Summary:');
console.log(`   Total actions processed: 7`);
console.log(`   Chains used: 0, 5, 24`);
console.log(`   Winner: Chain ${longestChainId} with ${longestChainLength} images`);

// Step 10: Verify the on-chain data
console.log('\n🔟 Verifying on-chain data...');

// Get the token ID
const tokenId = zkApp.deriveTokenId();
console.log(`🪙 Token ID: ${tokenId.toString()}`);

// Check the token account state
const tokenAccount = Mina.getAccount(tokenOwnerAccount, tokenId);
const storedChainId = tokenAccount.zkapp?.appState[0];
const storedHigh128 = tokenAccount.zkapp?.appState[1];
const storedLow128 = tokenAccount.zkapp?.appState[2];

// Reconstruct the SHA commitment from stored fields
const shaCommitment = new SHACommitment({
  bytes: verificationInputs.expectedHash,
});
const { high128: expectedHigh, low128: expectedLow } =
  shaCommitment.toTwoFields();

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
  `   Chain ID matches: ${storedChainId?.toString() === '0'}`
);
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


console.log('\n🎉 Example completed successfully!');
console.log('\nSummary:');
console.log(`- Image: ${imagePath} (${imageData.length} bytes)`);
console.log(`- SHA-256: ${imageHash}`);
console.log(`- Created by: ${creatorKey.toBigInt()}`);
console.log(`- Total images minted: ${Number(finalTotalCount.toBigint())}`);
console.log(`- Chain 0: ${Number(chain0Count.toBigint())} images`);
console.log(`- Chain 5: ${Number(chain5Count.toBigint())} images`);
console.log(`- Chain 24: ${Number(chain24Count.toBigint())} images`);
console.log(`- Token ID: Single shared tokenId (${tokenId.toString()})`);
console.log(`- Storage efficiency: ${(PackedImageChainCounters.TOTAL_BITS/254*100).toFixed(1)}% (${PackedImageChainCounters.TOTAL_BITS}/254 bits)`);