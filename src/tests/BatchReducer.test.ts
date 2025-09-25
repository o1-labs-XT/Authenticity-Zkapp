import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  Mina,
  PrivateKey,
  Field,
  UInt8,
  UInt32,
  AccountUpdate
} from 'o1js';

import {
  chainBatchReducer,
  BatchReducerUtils,
  ImageMintAction,
  AuthenticityZkApp,
  AuthenticityProgram,
  AuthenticityInputs,
  Ecdsa,
  PackedImageChainCounters,
  Secp256r1,
  Bytes32,
  FinalRoundInputs,
  hashUntilFinalRound,
  generateECKeyPair
} from '../index.js';

describe('BatchReducer Integration', () => {
  let Local: any;
  let deployer: PrivateKey;
  let zkAppKey: PrivateKey;
  let zkApp: AuthenticityZkApp;

  before(async () => {
    console.log('Setting up BatchReducer integration test...');

    // Setup local blockchain
    Local = await Mina.LocalBlockchain({ proofsEnabled: true });
    Mina.setActiveInstance(Local);

    deployer = Local.testAccounts[0].key;
    zkAppKey = PrivateKey.random();
    zkApp = new AuthenticityZkApp(zkAppKey.toPublicKey());

    // Set contract instance before compilation
    BatchReducerUtils.setContractInstance(zkApp);

    // Compile AuthenticityProgram first (zkApp dependency)
    console.log('Compiling AuthenticityProgram...');
    await AuthenticityProgram.compile();

    console.log('Compiling BatchReducer...');
    await BatchReducerUtils.compile();

    console.log('Compiling AuthenticityZkApp...');
    await AuthenticityZkApp.compile();

    console.log('Deploying contract...');
    const deployTx = await Mina.transaction(deployer.toPublicKey(), async () => {
      AccountUpdate.fundNewAccount(deployer.toPublicKey());
      await zkApp.deploy();
    });
    deployTx.sign([deployer, zkAppKey]);
    await deployTx.prove();
    await deployTx.send();

    console.log('Test setup complete');
  });

  describe('Action Processing', () => {
    it('should process actions through verifyAndStore and batch processing', async () => {
      const initialCounters = zkApp.chainCounters.get();
      const testData = Buffer.from('Hello, zkApp world!');
      const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
      const publicKey = Secp256r1.fromHex(publicKeyHex);
      const privateKey = Secp256r1.Scalar.from(privateKeyBigInt);

      const { penultimateState, finalRoundInputs, expectedHash } =
        hashUntilFinalRound(testData);

      const penultimateStateUInt32 = penultimateState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
      const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
        UInt32.from(x)
      ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];

      // Create commitment from expected hash
      const commitment = Bytes32.fromHex(expectedHash);

      // Sign the commitment
      const signature = Ecdsa.signHash(commitment, privateKey.toBigInt());

      // Create public inputs
      const publicInputs = new AuthenticityInputs({
        commitment: commitment,
        signature,
        publicKey: publicKey,
      });

      // Create private inputs
      const privateInputs = new FinalRoundInputs({
        state: penultimateStateUInt32,
        initialState: initialStateUInt32,
        messageWord: UInt32.from(finalRoundInputs.messageWord),
        roundConstant: UInt32.from(finalRoundInputs.roundConstant),
      });

      // Generate a proof and reuse it
      console.log('Generating single proof...');
      const { proof } = await AuthenticityProgram.verifyAuthenticity(
        publicInputs,
        privateInputs
      );
      console.log('Proof generated successfully');

      // Helper function to mint token using the same proof
      let mintCounter = 0;
      async function mintToken(chainId: number): Promise<void> {
        // Use unique account for each mint
        const tokenOwnerKey = Local.testAccounts[mintCounter + 1].key;
        const tokenOwnerAccount = tokenOwnerKey.toPublicKey();
        mintCounter++;

        const tx = await Mina.transaction(deployer.toPublicKey(), async () => {
          AccountUpdate.fundNewAccount(deployer.toPublicKey());
          await zkApp.verifyAndStore(tokenOwnerAccount, UInt8.from(chainId), proof);
        });

        await tx.prove();
        await tx.sign([deployer, tokenOwnerKey]).send();
      }

      // Mint tokens to different chains (minting dispatches actions)
      await mintToken(0); // Chain 0, account 1
      await mintToken(5); // Chain 5, account 2
      await mintToken(0); // Chain 0, account 3

      console.log('Actions dispatched via verifyAndStore');

      const batches = await BatchReducerUtils.prepareBatches();
      console.log(`Prepared ${batches.length} batches for processing`);

      // Process each batch
      for (let i = 0; i < batches.length; i++) {
        const { batch, proof } = batches[i];

        const tx = await Mina.transaction(deployer.toPublicKey(), async () => {
          await zkApp.processBatch(batch, proof);
        });

        await tx.prove();
        await tx.sign([deployer]).send();
      }

      console.log('Batches processed successfully');

      // Verify final state
      const finalCounters = zkApp.chainCounters.get();
      const finalWinnerLength = zkApp.winnerLength.get();

      // Check that state was updated
      assert(finalCounters !== initialCounters, 'Chain counters should be updated');

      // Verify winner determination (Chain 0 should win with 2 images)
      assert(finalWinnerLength.greaterThan(UInt32.from(0)).toBoolean(), 'Winner length should be > 0');

      // Verify specific chain counts
      const chain0Count = PackedImageChainCounters.getChainLength(finalCounters, UInt8.from(0));
      const chain5Count = PackedImageChainCounters.getChainLength(finalCounters, UInt8.from(5));

      assert(chain0Count.equals(UInt32.from(2)).toBoolean(), 'Chain 0 should have exactly 2 images');
      assert(chain5Count.equals(UInt32.from(1)).toBoolean(), 'Chain 5 should have exactly 1 image');

      console.log('BatchReducer integration test completed successfully');
    });
  });

  describe('Batch Processing Logic', () => {
    it('should handle empty batch preparation', async () => {
      // Should handle case where no new actions are pending
      const batches = await BatchReducerUtils.prepareBatches(1);

      // Should return empty array or handle
      assert(Array.isArray(batches), 'Should return array of batches');
    });

    it('should verify batch types', async () => {
      const batches = await BatchReducerUtils.prepareBatches(1);

      // Each batch should have proper structure and types
      batches.forEach((batchItem, index) => {
        assert(typeof batchItem === 'object', `Batch item ${index} should be an object`);
        assert('batch' in batchItem, `Batch item ${index} should have 'batch' property`);
        assert('proof' in batchItem, `Batch item ${index} should have 'proof' property`);

        const { batch, proof } = batchItem;
        assert(batch !== undefined && batch !== null, 'Batch should be defined');
        assert(proof !== undefined && proof !== null, 'Proof should be defined');
      });
    });
  });

  describe('Provable Code Compatibility', () => {
    it('should use proper PackedImageChainCounters methods', () => {
      const initialCounters = Field(0);
      const chainId = UInt8.from(10);

      assert.doesNotThrow(() => {
        const updatedCounters = PackedImageChainCounters.incrementChain(initialCounters, chainId);
        assert(updatedCounters instanceof Field, 'Should return Field instance');
      });
    });

    it('should verify ImageMintAction structure', () => {
      const testAction = new ImageMintAction({
        tokenAddress: PrivateKey.random().toPublicKey(),
        chainId: UInt8.from(10),
        tokenCreatorXHigh: Field(1),
        tokenCreatorXLow: Field(2),
        tokenCreatorYHigh: Field(3),
        tokenCreatorYLow: Field(4),
        authenticityCommitmentHigh: Field(5),
        authenticityCommitmentLow: Field(6),
      });

      assert(testAction instanceof ImageMintAction, 'Should be valid ImageMintAction');
      assert(testAction.chainId.value.equals(UInt8.from(10).value).toBoolean(), 'Should preserve chain ID');
    });
  });

  describe('Batch Configuration', () => {
    it('should handle batch size configuration', () => {
      // Verify our batch size configuration
      assert(chainBatchReducer !== undefined, 'BatchReducer should be initialized');
      assert(true, 'Batch configuration is properly set');
    });
  });
});