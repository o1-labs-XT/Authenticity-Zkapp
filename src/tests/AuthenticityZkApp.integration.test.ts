import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  VerificationKey,
  UInt32,
} from 'o1js';
import {
  AuthenticityProgram,
  AuthenticityInputs,
  AuthenticityZkApp,
  TokenAccountContract,
  FinalRoundInputs,
  hashUntilFinalRound,
  generateECKeyPair,
  Ecdsa,
  Secp256r1,
  SHACommitment,
  Secp256r1Commitment,
  Bytes32,
  MintEvent,
} from '../index.js';

describe('AuthenticityZkApp Integration Tests', () => {
  let Local: any;
  let deployer: Mina.TestPublicKey;
  let deployerKey: PrivateKey;
  let user1: Mina.TestPublicKey;
  let user1Key: PrivateKey;
  let user2: Mina.TestPublicKey;
  let user2Key: PrivateKey;

  let zkAppKey: PrivateKey;
  let zkAppAddress: PublicKey;
  let zkApp: AuthenticityZkApp;

  let challengeVk: VerificationKey;
  let tokenVk: VerificationKey;

  let testProof: any;
  let testInputs: AuthenticityInputs;

  // Token account addresses for shared access across tests
  let user1TokenAccountAddress: PublicKey;
  let user1TokenAccountPrivateKey: PrivateKey;

  before(async () => {
    console.log('🔧 Setting up test environment...');

    // Setup local blockchain
    Local = await Mina.LocalBlockchain({ proofsEnabled: true });
    Mina.setActiveInstance(Local);

    // Get test accounts
    [deployer, user1, user2] = Local.testAccounts;
    deployerKey = deployer.key;
    user1Key = user1.key;
    user2Key = user2.key;

    // Generate zkApp key
    zkAppKey = PrivateKey.random();
    zkAppAddress = zkAppKey.toPublicKey();
    zkApp = new AuthenticityZkApp(zkAppAddress);

    console.log('📝 Test accounts:');
    console.log('  Deployer:', deployer.toBase58());
    console.log('  User1:', user1.toBase58());
    console.log('  User2:', user2.toBase58());
    console.log('  ZkApp:', zkAppAddress.toBase58());
  });

  it('should compile all contracts', async () => {
    console.log('⚙️ Compiling contracts...');
    const startTime = Date.now();

    // Compile AuthenticityProgram first
    console.log('  - Compiling AuthenticityProgram...');
    await AuthenticityProgram.compile();

    // Compile contracts
    console.log('  - Compiling AuthenticityZkApp...');
    challengeVk = (await AuthenticityZkApp.compile()).verificationKey;

    console.log('  - Compiling TokenAccountContract...');
    tokenVk = (await TokenAccountContract.compile()).verificationKey;

    const endTime = Date.now();
    console.log(`✅ Compilation completed in ${(endTime - startTime) / 1000}s`);

    assert.ok(challengeVk);
    assert.ok(tokenVk);
  });

  it('should deploy and initialize AuthenticityZkApp', async () => {
    console.log('🚀 Deploying AuthenticityZkApp...');

    // Deploy contract (init() automatically initializes state)
    const deployTxn = await Mina.transaction(deployer, async () => {
      AccountUpdate.fundNewAccount(deployer);
      await zkApp.deploy();
    });
    await deployTxn.prove();
    await deployTxn.sign([deployerKey, zkAppKey]).send();

    const storedVkHash = zkApp.tokenAccountVkHash.get();
    // VK hash should match the compiled TokenAccountContract
    assert.equal(storedVkHash.toString(), '2500344745592430268173091005144987605594334572818740634112428059802822161761');

    console.log('✅ Contract deployed and auto-initialized');
    console.log('  VK Hash:', storedVkHash.toString());
  });
  it('should prepare valid authenticity proof', async () => {
    console.log('🔐 Preparing authenticity proof...');

    // Create test image data
    const testData = Buffer.from('Test image data for integration test');

    // Generate ECDSA keys for signing
    const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
    const publicKey = Secp256r1.fromHex(publicKeyHex);
    const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);

    // Hash the data until final round
    const { penultimateState, finalRoundInputs, expectedHash } = hashUntilFinalRound(testData);

    // Create commitment and signature
    const commitment = Bytes32.fromHex(expectedHash);
    const signature = Ecdsa.signHash(commitment, privateKey.toBigInt());

    // Create public and private inputs
    testInputs = new AuthenticityInputs({
      commitment,
      signature,
      publicKey,
    });

    const privateInputs = new FinalRoundInputs({
      state: penultimateState.map(x => UInt32.from(x)) as any,
      initialState: finalRoundInputs.initialState.map(x => UInt32.from(x)) as any,
      messageWord: UInt32.from(finalRoundInputs.messageWord),
      roundConstant: UInt32.from(finalRoundInputs.roundConstant),
    });

    // Generate proof
    const { proof } = await AuthenticityProgram.verifyAuthenticity(testInputs, privateInputs);
    testProof = proof;

    // Verify the proof
    const isValid = await AuthenticityProgram.verify(proof);
    assert.equal(isValid, true);

    console.log('✅ Valid proof generated and verified');
  });

  it('should mint token and create token account contract', async () => {
    console.log('🪙 Minting authenticity token...');

    const initialBalance = Mina.getBalance(user1);
    console.log('  User1 initial MINA balance:', initialBalance.div(1e9).toString());

    // Generate token account address (backend would do this)
    user1TokenAccountPrivateKey = PrivateKey.random();
    user1TokenAccountAddress = user1TokenAccountPrivateKey.toPublicKey();

    // Mint token to new token account address
    const mintTxn = await Mina.transaction(user1, async () => {
      AccountUpdate.fundNewAccount(user1); // Fund token account creation
      await zkApp.verifyAndStore(testProof, tokenVk, user1TokenAccountAddress);
    });
    await mintTxn.prove();
    // Both user (fee payer) and token account (authorizes creation) must sign
    await mintTxn.sign([user1Key, user1TokenAccountPrivateKey]).send();

    console.log('✅ Token minted successfully');


    // Verify token account exists (smart contract token accounts don't show balance via getBalance)
    const tokenId = zkApp.deriveTokenId();
    const tokenAccount = Mina.getAccount(user1TokenAccountAddress, tokenId);

    // The account should exist and have a verification key (meaning it's a smart contract)
    assert.ok(tokenAccount.zkapp?.verificationKey);
    console.log('  Token account created as smart contract ✓');

    // Verify events were emitted
    const events = await zkApp.fetchEvents();
    assert.equal(events.length, 1); // only mint event

    const mintEvent = events.find(e => e.type === 'mint');
    assert.ok(mintEvent);

    // Verify mint event contains token ID
    const mintEventData = mintEvent.event.data as unknown as MintEvent;
    assert.ok(mintEventData.tokenId);

    console.log('✅ Events emitted correctly');
    console.log('  Mint event data:', mintEvent?.event.data);
  });

  it('should verify token account contract state', async () => {
    console.log('🔍 Verifying token account contract state...');

    const tokenId = zkApp.deriveTokenId();
    const tokenContract = new TokenAccountContract(user1TokenAccountAddress, tokenId);

    // Read all state fields
    const shaHashHigh = tokenContract.shaHashHigh.get();
    const shaHashLow = tokenContract.shaHashLow.get();
    const creatorXHigh = tokenContract.creatorXHigh.get();
    const creatorXLow = tokenContract.creatorXLow.get();
    const creatorYHigh = tokenContract.creatorYHigh.get();
    const creatorYLow = tokenContract.creatorYLow.get();

    // Note: Ownership is implicit - whoever controls this token account address owns it
    console.log('  Token authenticity data verified');

    // Verify SHA commitment
    const shaCommitment = new SHACommitment({
      bytes: new Bytes32(testInputs.commitment.bytes),
    });
    const { high128: expectedShaHigh, low128: expectedShaLow } = shaCommitment.toTwoFields();
    assert.equal(shaHashHigh.toString(), expectedShaHigh.toString());
    assert.equal(shaHashLow.toString(), expectedShaLow.toString());

    // Verify creator public key commitment
    const creatorCommitment = Secp256r1Commitment.fromPublicKey(testInputs.publicKey);
    const { xHigh128, xLow128, yHigh128, yLow128 } = creatorCommitment.toFourFields();
    assert.equal(creatorXHigh.toString(), xHigh128.toString());
    assert.equal(creatorXLow.toString(), xLow128.toString());
    assert.equal(creatorYHigh.toString(), yHigh128.toString());
    assert.equal(creatorYLow.toString(), yLow128.toString());

    console.log('✅ Token account contract state verified correctly');
    console.log('  Authenticity data verified ✓');
    console.log('  SHA high:', shaHashHigh.toString());
    console.log('  SHA low:', shaHashLow.toString());
  });


  it('should reject wrong verification key', async () => {
    console.log('🚫 Testing VK validation...');

    // Try to use wrong VK (use challenge VK instead of token VK)
    const wrongVk = challengeVk;

    // Generate token account for this test
    const user2TokenAccountPrivateKey = PrivateKey.random();
    const user2TokenAccountAddress = user2TokenAccountPrivateKey.toPublicKey();

    try {
      const invalidTxn = await Mina.transaction(user2, async () => {
        AccountUpdate.fundNewAccount(user2);
        await zkApp.verifyAndStore(testProof, wrongVk, user2TokenAccountAddress);
      });
      await invalidTxn.prove();
      // Both user (fee payer) and token account (authorizes creation) must sign
      await invalidTxn.sign([user2Key, user2TokenAccountPrivateKey]).send();

      // Should not reach here
      assert.fail('Expected transaction to fail with wrong VK');
    } catch (error) {
      console.log('✅ Correctly rejected wrong verification key');
      console.log('  Error:', (error as Error).message);
      assert.ok((error as Error).message.includes('assert') || (error as Error).message.includes('failed') || (error as Error).message.includes('fromFields'));
    }
  });

  it('should handle multiple token mints correctly', async () => {
    console.log('🔢 Testing multiple token mints...');

    // Generate token account for user2
    const user2MultiTokenAccountPrivateKey = PrivateKey.random();
    const user2MultiTokenAccountAddress = user2MultiTokenAccountPrivateKey.toPublicKey();

    // Mint second token to user2
    const mintTxn = await Mina.transaction(user2, async () => {
      AccountUpdate.fundNewAccount(user2);
      await zkApp.verifyAndStore(testProof, tokenVk, user2MultiTokenAccountAddress);
    });
    await mintTxn.prove();
    // Both user (fee payer) and token account (authorizes creation) must sign
    await mintTxn.sign([user2Key, user2MultiTokenAccountPrivateKey]).send();


    // Verify both users have token accounts (smart contracts)
    const tokenId = zkApp.deriveTokenId();
    const user1TokenAccount = Mina.getAccount(user1TokenAccountAddress, tokenId);
    const user2TokenAccount = Mina.getAccount(user2MultiTokenAccountAddress, tokenId);

    // Both accounts should exist as smart contracts
    assert.ok(user1TokenAccount.zkapp?.verificationKey);
    assert.ok(user2TokenAccount.zkapp?.verificationKey);

    console.log('✅ Multiple token smart contracts created successfully');
    console.log('  User1 token account: smart contract ✓');
    console.log('  User2 token account: smart contract ✓');
  });

  // Test removed: setChallengeId method no longer exists (challengeId is fixed at deployment)

  after(() => {
    console.log('🧹 Integration tests completed');
  });
});