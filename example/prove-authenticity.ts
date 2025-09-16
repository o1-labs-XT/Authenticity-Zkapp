import {
  AuthenticityProgram,
  AuthenticityInputs,
  FinalRoundInputs,
  prepareImageVerification,
  AuthenticityZkApp,
  ImageMintAction,
  PackedImageChainCounters,
  SHACommitment,
  hashImageOffCircuit,
  computeOnChainCommitment,
  generateECKeyPair,
  Ecdsa,
  Secp256r1,
  Secp256r1Commitment,
} from '../src/index.js';
import { PrivateKey, Mina, AccountUpdate, UInt8 } from 'o1js';
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
console.log('✅ Contract deployed with initialized chain counters\n');

// Step 8: Verify and store image metadata on-chain
console.log('8️⃣ Storing image authenticity on-chain with multiple image chains...');

// Show initial chain state
console.log('\n   📊 Initial Chain State:');
const initialTotalCount = PackedImageChainCounters.getTotalImageCount(zkApp.chainCounters.getAndRequireEquals());
console.log(`   Total images across all chains: ${Number(initialTotalCount.toBigint())}`);

// Mint image to Chain 0
console.log('\n   🌱 Minting to Chain 0...');
const chain0Txn = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwnerAccount, UInt8.from(0), proof);
});
await chain0Txn.prove();
await chain0Txn.sign([payerKey, tokenOwnerKey]).send();

// Create another token owner, for Chain 5
const tokenOwner2Key = Local.testAccounts[4].key;
const tokenOwner2Account = tokenOwner2Key.toPublicKey();

// Mint image to Chain 5
console.log('   ☕ Minting to Chain 5...');
const chain5Txn = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner2Account, UInt8.from(5), proof);
});
await chain5Txn.prove();
await chain5Txn.sign([payerKey, tokenOwner2Key]).send();

// Create another token owner, for Chain 24 (max chain to test full range)
const tokenOwner3Key = Local.testAccounts[5].key;
const tokenOwner3Account = tokenOwner3Key.toPublicKey();

// Mint image to Chain 24
console.log('   🔚 Minting to Chain 24...');
const chain24Txn = await Mina.transaction(payerAccount, async () => {
  AccountUpdate.fundNewAccount(payerAccount);
  await zkApp.verifyAndStore(tokenOwner3Account, UInt8.from(24), proof);
});
await chain24Txn.prove();
await chain24Txn.sign([payerKey, tokenOwner3Key]).send();

console.log('✅ All chain mints completed!\n');

// Display chain counter statistics
console.log('📊 Chain Counter Statistics:');
const finalTotalCount = PackedImageChainCounters.getTotalImageCount(zkApp.chainCounters.getAndRequireEquals());
const chain0Count = PackedImageChainCounters.getChainLength(zkApp.chainCounters.getAndRequireEquals(), UInt8.from(0));
const chain5Count = PackedImageChainCounters.getChainLength(zkApp.chainCounters.getAndRequireEquals(), UInt8.from(5));
const chain24Count = PackedImageChainCounters.getChainLength(zkApp.chainCounters.getAndRequireEquals(), UInt8.from(24));
const chain2Count = PackedImageChainCounters.getChainLength(zkApp.chainCounters.getAndRequireEquals(), UInt8.from(2)); // Should be 0

console.log(`   Total images: ${Number(finalTotalCount.toBigint())}`);
console.log(`   Chain 0 count: ${Number(chain0Count.toBigint())}`);
console.log(`   Chain 5 count: ${Number(chain5Count.toBigint())}`);
console.log(`   Chain 24 count: ${Number(chain24Count.toBigint())}`);
console.log(`   Chain 2 count (unused): ${Number(chain2Count.toBigint())}`);

// Step 9: Verify mint action was dispatched correctly
console.log('9️⃣ Verifying mint action...');

// For LocalBlockchain, we can use getActions() directly
// For real networks, we would need fetchActions() with archive node configuration
const actions = await zkApp.reducer.getActions();

let totalActions = 0;
let lastAction: ImageMintAction | null = null;

// Iterate through the MerkleList of action blocks
const outerIterator = actions.startIterating();
while (!outerIterator.isAtEnd().toBoolean()) {
  const actionBlock = outerIterator.next();

  // Iterate through actions in this block
  const innerIterator = actionBlock.startIterating();
  while (!innerIterator.isAtEnd().toBoolean()) {
    const action = innerIterator.next() as ImageMintAction;
    totalActions++;
    lastAction = action; // Keep updating to get the latest
  }
}

console.log(`   Total actions dispatched: ${totalActions}`);

if (lastAction) {
  console.log('\n   Latest Action Data:');
  console.log(`   - Token Address: ${lastAction.tokenAddress.toBase58()}`);
  console.log(`   - Chain ID: ${Number(lastAction.chainId.toBigInt())}`);
  console.log(`   - Image Count: ${Number(lastAction.imageCount.toBigInt())}`);

  // Reconstruct creator public key from compressed fields
  const actionCreatorCommitment = Secp256r1Commitment.fromFourFields(
    lastAction.tokenCreatorXHigh,
    lastAction.tokenCreatorXLow,
    lastAction.tokenCreatorYHigh,
    lastAction.tokenCreatorYLow
  );
  const actionCreatorKey = actionCreatorCommitment.toPublicKey();
  console.log(`   - Token Creator x: ${actionCreatorKey.x.toBigInt()}`);
  console.log(`   - Token Creator y: ${actionCreatorKey.y.toBigInt()}`);

  // Reconstruct SHA commitment from compressed fields
  const actionShaCommitment = SHACommitment.fromTwoFields(
    lastAction.authenticityCommitmentHigh,
    lastAction.authenticityCommitmentLow
  );
  console.log(`   - Commitment: ${actionShaCommitment.toHex()}`);

  // Verify action data matches expected values (check against the last mint which was to tokenOwner3Account)
  console.log('\n   Mint Action Verification:');
  console.log(
    `   - Token address matches: ${lastAction.tokenAddress
      .equals(tokenOwner3Account)
      .toBoolean()}`
  );

  // Compare the reconstructed key with the original
  const keysMatch =
    actionCreatorKey.x.toBigInt() === creatorPublicKey.x.toBigInt() &&
    actionCreatorKey.y.toBigInt() === creatorPublicKey.y.toBigInt();
  console.log(`   - Creator public key matches: ${keysMatch}`);
  console.log(
    `   - Commitment matches: ${actionShaCommitment.toHex() === imageHash}`
  );
} else {
  console.log('   ❌ No actions found!');
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
console.log(`- Created by: ${creatorKey.toBigInt()}`);
console.log(`\n🔗 Chain Storage Results:`);
console.log(`- Total chains deployed: 3 (chains 0, 5, 24)`);
console.log(`- Total images minted: ${Number(finalTotalCount.toBigint())}`);
console.log(`- Chain 0: ${Number(chain0Count.toBigint())} images`);
console.log(`- Chain 5: ${Number(chain5Count.toBigint())} images`);
console.log(`- Chain 24: ${Number(chain24Count.toBigint())} images`);
console.log(`- Token ID: Single shared tokenId (${tokenId.toString()})`);
console.log(`- Storage efficiency: ${(PackedImageChainCounters.TOTAL_BITS/254*100).toFixed(1)}% (${PackedImageChainCounters.TOTAL_BITS}/254 bits)`);
console.log(`- Max capacity: ${PackedImageChainCounters.CHAIN_COUNT} chains × ${PackedImageChainCounters.MAX_PER_CHAIN} images = ${PackedImageChainCounters.CHAIN_COUNT * PackedImageChainCounters.MAX_PER_CHAIN} total images`);