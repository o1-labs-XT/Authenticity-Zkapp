import 'dotenv/config';
import {
  AccountUpdate,
  Lightnet,
  Mina,
  PrivateKey,
  PublicKey,
  UInt8,
  fetchAccount,
  fetchLastBlock,
} from 'o1js';
import fs from 'fs';
import path from 'path';

import {
  AuthenticityProgram,
  AuthenticityZkApp,
  BatchReducerUtils,
  FinalRoundInputs,
  AuthenticityInputs,
  Ecdsa,
  Secp256r1,
  prepareImageVerification,
  hashImageOffCircuit,
  computeOnChainCommitment,
  generateECKeyPair,
} from '../src/index.js';

type BatchRecord = {
  id: number;
  txHash: string;
  submittedHeight: number;
  includedHeight?: number;
  chainStatus?: string;
  abandoned?: boolean;
};

type MonitorState = {
  submittedTxs: Map<string, number>; // txHash -> submittedHeight
  batches: BatchRecord[];
  observedActionHashes: Set<string>;
  seenEventKeys: Set<string>;
  processedTransactionHashes: Set<string>;
};

const LIGHTNET = {
  mina: process.env.LIGHTNET_MINA_ENDPOINT ?? 'http://127.0.0.1:8080/graphql',
  archive: process.env.LIGHTNET_ARCHIVE_ENDPOINT ?? 'http://127.0.0.1:8282',
  accountManager:
    process.env.LIGHTNET_ACCOUNT_MANAGER_ENDPOINT ?? 'http://127.0.0.1:8181',
  defaultFee: 0.1e9,
} as const;

const POLL_INTERVAL_MS = 5_000;

async function fetchActionsWithBlockInfo(
  address: string,
  fromHeight: number,
  toHeight: number,
  archiveEndpoint: string,
  logRequest = false
): Promise<
  {
    blockInfo: { height: number; distanceFromMaxBlockHeight: number };
    actionData: { transactionInfo: { status: string; hash: string } }[];
  }[]
> {
  const query = `
    {
      actions(
        input: {address: "${address}", from: ${fromHeight}, to: ${toHeight}}
      ) {
        blockInfo {
          height
          distanceFromMaxBlockHeight
        }
        actionData {
          transactionInfo {
            status
            hash
          }
        }
      }
    }
  `;

  if (logRequest) {
    console.log('GraphQL request:', query);
  }

  const response = await fetch(archiveEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query }),
  });

  if (!response.ok) {
    throw new Error(`GraphQL request failed: ${response.statusText}`);
  }

  const result = await response.json();

  if (result.errors) {
    throw new Error(`GraphQL errors: ${JSON.stringify(result.errors)}`);
  }

  return result.data?.actions || [];
}

async function main() {
  const waitBlocks = 5; // Number of blocks to wait for finality

  console.log('🚀 Authenticity archive demo on Lightnet');
  console.log(`ℹ️ Waiting for ${waitBlocks} blocks before declaring finality`);

  const payerKeys = await Lightnet.acquireKeyPair({
    isRegularAccount: true,
    lightnetAccountManagerEndpoint: LIGHTNET.accountManager,
  });
  const zkAppKey = PrivateKey.random();

  try {
    const payerKey = payerKeys.privateKey;

    const zkApp = await ensureDeployment(payerKey, zkAppKey);

    const payerAddress = payerKey.toPublicKey();
    await fetchAccountOrThrow(payerAddress);
    console.log(`💳 Using payer ${payerAddress.toBase58()}`);

    const proofData = await prepareAuthenticityProof();
    console.log(`🧠 Proof commitment ${proofData.sha.hex}`);

    const mintActors: MintActor[] = [
      createMintActor('Tracked case'),
      createMintActor('Replacement case'),
      ...Array.from({ length: 3 }, (_, i) =>
        createMintActor(`Follow-up ${i + 1}`)
      ),
    ];

    mintActors.forEach((actor) =>
      console.log(`👤 ${actor.label}: ${actor.publicKey.toBase58()}`)
    );

    let nextNonce = await fetchNonce(payerAddress);
    console.log(`🔢 Starting nonce ${nextNonce}`);

    const state: MonitorState = {
      submittedTxs: new Map(),
      batches: [],
      observedActionHashes: new Set(),
      seenEventKeys: new Set(),
      processedTransactionHashes: new Set(),
    };

    const mintSchedule: Array<{
      tick: number;
      actor: MintActor;
      chainId: number;
    }> = [
      { tick: 0, actor: mintActors[0], chainId: 0 },
      { tick: 2, actor: mintActors[1], chainId: 1 },
      { tick: 4, actor: mintActors[2], chainId: 2 },
      { tick: 6, actor: mintActors[3], chainId: 3 },
      { tick: 8, actor: mintActors[4], chainId: 4 },
    ];

    const batchSubmissionTick = 10;
    let batchSubmitted = false;

    const totalTicks = 15;

    for (let tick = 0; tick < totalTicks; tick++) {
      console.log(`\n⏱️ Poll tick ${tick + 1}/${totalTicks}`);

      const scheduledMints = mintSchedule.filter((item) => item.tick === tick);
      for (const scheduled of scheduledMints) {
        await waitForHeightAdvance();
        const submissionHeight = await fetchBestHeight();
        const txResult = await sendVerifyAndStoreTx({
          zkApp,
          payer: payerKey,
          tokenOwner: scheduled.actor.privateKey,
          chainId: scheduled.chainId,
          proof: proofData.proof,
          fee: LIGHTNET.defaultFee,
          nonce: nextNonce,
          memo: `mint-${scheduled.actor.label}`,
        });
        nextNonce += 1;
        if (txResult.success && txResult.hash) {
          state.submittedTxs.set(txResult.hash, submissionHeight);
          console.log(
            `   ➕ Mint tx sent: ${txResult.hash} (height ${submissionHeight})`
          );
        }
      }

      if (!batchSubmitted && tick >= batchSubmissionTick) {
        if (state.observedActionHashes.size >= 2) {
          await waitForHeightAdvance();
          const submissionHeight = await fetchBestHeight();
          const txResult = await sendProcessBatchTx({
            zkApp,
            payer: payerKey,
            fee: LIGHTNET.defaultFee,
            nonce: nextNonce,
          });
          nextNonce += 1;
          if (txResult.success && txResult.hash) {
            batchSubmitted = true;
            state.batches.push({
              id: state.batches.length + 1,
              txHash: txResult.hash,
              submittedHeight: submissionHeight,
            });
            console.log(`   📦 Batch tx sent: ${txResult.hash}`);
          }
        }
      }

      await pollArchive(zkApp, state, waitBlocks);

      if (tick < totalTicks - 1) {
        await sleep(POLL_INTERVAL_MS);
      }
    }

    console.log('\n✅ Monitoring complete');
  } finally {
    await Lightnet.releaseKeyPair({
      publicKey: payerKeys.publicKey.toBase58(),
      lightnetAccountManagerEndpoint: LIGHTNET.accountManager,
    }).catch(() => undefined);
  }
}

type MintActor = {
  privateKey: PrivateKey;
  publicKey: PublicKey;
  label: string;
};

function createMintActor(label: string): MintActor {
  const privateKey = PrivateKey.random();
  return {
    privateKey,
    publicKey: privateKey.toPublicKey(),
    label,
  };
}

async function ensureDeployment(payer: PrivateKey, zkAppKey: PrivateKey) {
  await setupNetwork();
  const payerAddress = payer.toPublicKey();
  const zkAppAddress = zkAppKey.toPublicKey();
  console.log(`🛠️ Deploying zkApp to ${zkAppAddress.toBase58()}`);
  await waitForAccount(payerAddress, 'payer');

  const zkApp = new AuthenticityZkApp(zkAppAddress);
  BatchReducerUtils.setContractInstance(zkApp);

  const programStart = Date.now();
  await AuthenticityProgram.compile();
  console.log(`⏱️ AuthenticityProgram compiled in ${elapsed(programStart)}s`);

  const reducerStart = Date.now();
  await BatchReducerUtils.compile();
  console.log(`⏱️ BatchReducer compiled in ${elapsed(reducerStart)}s`);

  const contractStart = Date.now();
  const { verificationKey } = await AuthenticityZkApp.compile();
  console.log(`⏱️ AuthenticityZkApp compiled in ${elapsed(contractStart)}s`);

  const fee = LIGHTNET.defaultFee;
  const deployTx = await Mina.transaction(
    { sender: payerAddress, fee },
    async () => {
      AccountUpdate.fundNewAccount(payerAddress);
      await zkApp.deploy({ verificationKey });
    }
  );

  await deployTx.prove();
  const sent = await deployTx.sign([payer, zkAppKey]).send();
  if (sent.status !== 'pending') {
    throw new Error(`Deployment failed to send: ${JSON.stringify(sent)}`);
  }
  console.log(`📤 Deployment sent ${sent.hash}`);

  await waitForAccount(zkAppAddress, 'zkApp', 15);
  await waitForZkAppVerificationKey(zkAppAddress);

  return zkApp;
}

async function setupNetwork() {
  const network = Mina.Network({
    mina: LIGHTNET.mina,
    archive: LIGHTNET.archive,
    lightnetAccountManager: LIGHTNET.accountManager,
    bypassTransactionLimits: true,
  });
  Mina.setActiveInstance(network);
}

function elapsed(start: number) {
  return ((Date.now() - start) / 1000).toFixed(1);
}

async function prepareAuthenticityProof() {
  const imagePath = path.join(process.cwd(), 'build', 'example', 'cat.png');
  const imageBuffer = await fs.promises.readFile(imagePath);
  console.log(`📷 Loaded image ${imagePath}`);
  console.log(`   SHA-256 hash ${hashImageOffCircuit(imageBuffer)}`);

  const verificationInputs = prepareImageVerification(imagePath);

  const { privateKeyBigInt, publicKeyHex } = generateECKeyPair();
  const secpPrivate = Secp256r1.Scalar.from(privateKeyBigInt);
  const secpPublic = Secp256r1.fromHex(publicKeyHex);
  const signature = Ecdsa.signHash(
    verificationInputs.expectedHash,
    secpPrivate.toBigInt()
  );

  const publicInputs = new AuthenticityInputs({
    commitment: verificationInputs.expectedHash,
    signature,
    publicKey: secpPublic,
  });

  const privateInputs = new FinalRoundInputs({
    state: verificationInputs.penultimateState,
    initialState: verificationInputs.initialState,
    messageWord: verificationInputs.messageWord,
    roundConstant: verificationInputs.roundConstant,
  });

  console.log('🧾 Generating authenticity proof');
  const { proof } = await AuthenticityProgram.verifyAuthenticity(
    publicInputs,
    privateInputs
  );
  const commitment = await computeOnChainCommitment(imageBuffer);

  return {
    proof,
    sha: {
      hex: commitment.sha256,
      high: commitment.high128,
      low: commitment.low128,
    },
  };
}

async function fetchAccountOrThrow(publicKey: PublicKey) {
  const response = await fetchAccount({ publicKey }, LIGHTNET.mina);
  if (!response.account) {
    throw new Error(`Account ${publicKey.toBase58()} not found on chain`);
  }
  return response.account;
}

async function fetchNonce(publicKey: PublicKey): Promise<number> {
  const account = await fetchAccountOrThrow(publicKey);
  return Number(account.nonce ?? 0);
}

async function waitForAccount(
  publicKey: PublicKey,
  label: string,
  attempts = 20
) {
  for (let i = 1; i <= attempts; i++) {
    try {
      const result = await fetchAccount({ publicKey }, LIGHTNET.mina);
      if (result.account) return;
    } catch (error) {
      // ignore and continue polling
    }
    console.log(
      `${new Date().toISOString()} Waiting for ${label} account ${publicKey.toBase58()} on Lightnet (attempt ${i}/${attempts})`
    );
    await sleep(8_000);
  }
  throw new Error(
    `Account ${publicKey.toBase58()} not found after waiting on Lightnet`
  );
}

async function waitForZkAppVerificationKey(
  publicKey: PublicKey,
  attempts = 30
) {
  for (let i = 1; i <= attempts; i++) {
    try {
      const result = await fetchAccount({ publicKey }, LIGHTNET.mina);
      const vk = result.account?.zkapp?.verificationKey?.data;
      if (vk) return;
    } catch (error) {
      // ignore and continue polling
    }
    console.log(
      `${new Date().toISOString()} Waiting for zkApp verification key at ${publicKey.toBase58()} (attempt ${i}/${attempts})`
    );
    await sleep(2_000);
  }
  console.warn(
    `⚠️ Timed out waiting for zkApp verification key at ${publicKey.toBase58()} — continuing`
  );
}

async function sendVerifyAndStoreTx(params: {
  zkApp: AuthenticityZkApp;
  payer: PrivateKey;
  tokenOwner: PrivateKey;
  chainId: number;
  proof: Awaited<
    ReturnType<typeof AuthenticityProgram.verifyAuthenticity>
  >['proof'];
  fee: number;
  nonce: number;
  memo?: string;
}): Promise<{ success: boolean; hash?: string }> {
  const payerAddress = params.payer.toPublicKey();
  const ownerAddress = params.tokenOwner.toPublicKey();

  const tx = await Mina.transaction(
    {
      sender: payerAddress,
      fee: params.fee,
      memo: params.memo ?? 'verifyAndStore',
      nonce: params.nonce,
    },
    async () => {
      AccountUpdate.fundNewAccount(payerAddress);
      await params.zkApp.verifyAndStore(
        ownerAddress,
        UInt8.from(params.chainId),
        params.proof
      );
    }
  );

  await tx.prove();
  const response = await tx.sign([params.payer, params.tokenOwner]).send();
  if (response.status !== 'pending') {
    console.error('   ❌ Mint send failed', response);
    return { success: false };
  }
  console.log(`   📮 Mint transaction sent (nonce ${params.nonce})`);
  return { success: true, hash: response.hash };
}

async function sendProcessBatchTx(params: {
  zkApp: AuthenticityZkApp;
  payer: PrivateKey;
  fee: number;
  nonce: number;
}): Promise<{ success: boolean; hash?: string }> {
  const batches = await BatchReducerUtils.prepareBatches();
  if (!batches.length) {
    console.log('   ⚠️ No actions available for batch processing yet');
    return { success: false };
  }

  const payerAddress = params.payer.toPublicKey();
  const tx = await Mina.transaction(
    {
      sender: payerAddress,
      fee: params.fee,
      memo: 'processBatch',
      nonce: params.nonce,
    },
    async () => {
      for (const { batch, proof } of batches) {
        await params.zkApp.processBatch(batch, proof);
      }
    }
  );

  await tx.prove();
  const response = await tx.sign([params.payer]).send();
  if (response.status !== 'pending') {
    console.error('   ❌ Batch transaction failed to send', response);
    return { success: false };
  }
  console.log(`   📨 Batch transaction sent (nonce ${params.nonce})`);
  return { success: true, hash: response.hash };
}

async function pollArchive(
  zkApp: AuthenticityZkApp,
  state: MonitorState,
  waitBlocks: number
) {
  const bestHeight = await fetchBestHeight();
  const mintedSummary = await summarizeActions(
    zkApp,
    state,
    bestHeight,
    waitBlocks
  );

  console.log(
    `   📊 Actions — submitted:${mintedSummary.submitted} pending:${
      mintedSummary.pending
    }${
      mintedSummary.pendingTxs.length
        ? ` [${mintedSummary.pendingTxs.join(',')}]`
        : ''
    } included:${mintedSummary.included}${
      mintedSummary.includedTxs.length
        ? ` [${mintedSummary.includedTxs.join(',')}]`
        : ''
    } final:${mintedSummary.final}${
      mintedSummary.finalTxs.length
        ? ` [${mintedSummary.finalTxs.join(',')}]`
        : ''
    } abandoned:${mintedSummary.abandoned}${
      mintedSummary.abandonedTxs.length
        ? ` [${mintedSummary.abandonedTxs.join(',')}]`
        : ''
    }`
  );
}

async function summarizeActions(
  zkApp: AuthenticityZkApp,
  state: MonitorState,
  bestHeight: number,
  waitBlocks: number
) {
  try {
    // Query recent block range for actions
    const fromHeight = Math.max(1, bestHeight - 100); // Look back 100 blocks
    const toHeight = bestHeight;

    const actionsResponse = await fetchActionsWithBlockInfo(
      zkApp.address.toBase58(),
      fromHeight,
      toHeight,
      LIGHTNET.archive
    );

    // Process each action and match to submitted transactions
    for (const entry of actionsResponse) {
      const txHash = entry.actionData?.[0]?.transactionInfo?.hash;
      if (txHash && !state.processedTransactionHashes.has(txHash)) {
        state.processedTransactionHashes.add(txHash);

        if (state.submittedTxs.has(txHash)) {
          console.log(
            `   ✅ Mint tx ${txHash.slice(0, 8)}... included at height ${
              entry.blockInfo.height
            }`
          );
        }
      }
    }

    return aggregateCounts(
      state.submittedTxs,
      actionsResponse,
      bestHeight,
      waitBlocks
    );
  } catch (error) {
    console.error('   ⚠️ Failed to fetch actions via GraphQL:', error);
    return aggregateCounts(state.submittedTxs, [], bestHeight, waitBlocks);
  }
}

function aggregateCounts(
  submittedTxs: Map<string, number>,
  actionsResponse: {
    blockInfo: { height: number; distanceFromMaxBlockHeight: number };
    actionData: { transactionInfo: { status: string; hash: string } }[];
  }[],
  bestHeight: number,
  waitBlocks: number
) {
  let pending = 0;
  let included = 0;
  let final = 0;
  let abandoned = 0;

  const pendingTxs: string[] = [];
  const includedTxs: string[] = [];
  const finalTxs: string[] = [];
  const abandonedTxs: string[] = [];

  const totalSubmitted = submittedTxs.size;
  const matchedTxHashes = new Set<string>();

  // Iterate over GraphQL response and match transaction hashes
  for (const entry of actionsResponse) {
    for (const actionData of entry.actionData) {
      const txHash = actionData.transactionInfo.hash;
      const distanceFromMax = entry.blockInfo.distanceFromMaxBlockHeight || 0;

      if (txHash && submittedTxs.has(txHash)) {
        matchedTxHashes.add(txHash);

        // Use distanceFromMaxBlockHeight for confirmations calculation
        // If distance is negative, it means blocks have advanced beyond this block
        const confirmations = Math.abs(distanceFromMax);

        if (confirmations >= waitBlocks) {
          final += 1;
          finalTxs.push(txHash.slice(0, 8));
        } else {
          included += 1;
          includedTxs.push(txHash.slice(0, 8));
        }
      }
    }
  }

  // Check remaining submitted transactions for pending/abandoned status
  for (const [txHash, submittedHeight] of submittedTxs) {
    if (!matchedTxHashes.has(txHash)) {
      const blocksSinceSubmission = bestHeight - submittedHeight;

      if (blocksSinceSubmission > 15) {
        abandoned += 1;
        abandonedTxs.push(txHash.slice(0, 8));
      } else {
        pending += 1;
        pendingTxs.push(txHash.slice(0, 8));
      }
    }
  }

  return {
    submitted: totalSubmitted,
    pending,
    included,
    final,
    abandoned,
    pendingTxs,
    includedTxs,
    finalTxs,
    abandonedTxs,
  };
}

async function fetchBestHeight(): Promise<number> {
  const response = await fetchLastBlock(LIGHTNET.mina);
  return Number(response.blockchainLength.toBigint());
}

async function waitForHeightAdvance(attempts = 20) {
  const startHeight = await fetchBestHeight();
  for (let i = 0; i < attempts; i++) {
    await sleep(2_000);
    const currentHeight = await fetchBestHeight();
    if (currentHeight > startHeight) return;
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((error) => {
  console.error('❌ Fatal error in query-events-and-actions demo');
  console.error(error);
  process.exit(1);
});
