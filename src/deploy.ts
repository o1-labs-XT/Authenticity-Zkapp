import { Mina, PrivateKey, AccountUpdate } from 'o1js';
import { AuthenticityZkApp } from './AuthenticityZkApp.js';
import { BatchReducerUtils } from './BatchReducer.js';
import * as dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

// Load environment variables
dotenv.config();

// Network configurations
const NETWORKS = {
  devnet: {
    url: 'https://api.minascan.io/node/devnet/v1/graphql',
    explorer: 'https://minascan.io/devnet',
    payerPrivateKeyEnv: 'DEVNET_PAYER_PRIVATE_KEY',
    zkAppPrivateKeyEnv: 'DEVNET_ZKAPP_PRIVATE_KEY',
  },
  mainnet: {
    url: 'https://api.minascan.io/node/mainnet/v1/graphql',
    explorer: 'https://minascan.io/mainnet',
    payerPrivateKeyEnv: 'MAINNET_PAYER_PRIVATE_KEY',
    zkAppPrivateKeyEnv: 'MAINNET_ZKAPP_PRIVATE_KEY',
  },
  zeko: {
    url: 'https://devnet.zeko.io/graphql',
    explorer: 'https://zekoscan.io',
    payerPrivateKeyEnv: 'ZEKO_PAYER_PRIVATE_KEY',
    zkAppPrivateKeyEnv: 'ZEKO_ZKAPP_PRIVATE_KEY',
  },
} as const;

type NetworkName = keyof typeof NETWORKS;

// Parse command line arguments
const args = process.argv.slice(2);
const networkName = args[0] as NetworkName;

if (!networkName || !NETWORKS[networkName]) {
  console.error('❌ Please specify a valid network: devnet, mainnet, or zeko');
  console.error('Usage: npm run deploy <network>');
  process.exit(1);
}

// Get network configuration
const network = NETWORKS[networkName];
const payerPrivateKey = process.env[network.payerPrivateKeyEnv];
const zkAppPrivateKey = process.env[network.zkAppPrivateKeyEnv];

if (!payerPrivateKey || !zkAppPrivateKey) {
  console.error('❌ Missing required private keys in .env file.');
  if (!payerPrivateKey) {
    console.error(
      `   Missing ${network.payerPrivateKeyEnv} (payer account for transaction fees)`
    );
  }
  if (!zkAppPrivateKey) {
    console.error(
      `   Missing ${network.zkAppPrivateKeyEnv} (zkApp deployment address)`
    );
  }
  console.error('\nExample .env file:');
  console.error(`${network.payerPrivateKeyEnv}=EKE...`);
  console.error(`${network.zkAppPrivateKeyEnv}=EKE...`);
  process.exit(1);
}

console.log(`🚀 Deploying AuthenticityZkApp to ${networkName}\n`);

// Main deployment function
async function deploy() {
  try {
    // Connect to network
    console.log(`📡 Connecting to ${networkName}...`);
    const Network = Mina.Network(network.url);
    Mina.setActiveInstance(Network);
    console.log('✅ Connected to network\n');

    // Load payer account
    console.log('🔑 Loading payer account...');
    const payerKey = PrivateKey.fromBase58(payerPrivateKey!);
    const payerPublicKey = payerKey.toPublicKey();
    console.log(`   Payer address: ${payerPublicKey.toBase58()}`);

    // Fetch payer account info
    try {
      Mina.getAccount(payerPublicKey);
      const account = Mina.getAccount(payerPublicKey);
      console.log(`   Balance: ${account.balance.div(1e9).toString()} MINA`);
    } catch (error) {
      console.error(
        '   ⚠️  Could not fetch payer account info. Account might not exist or have no balance.'
      );
    }
    console.log();

    // Load zkApp account
    console.log('🔐 Loading zkApp account...');
    const zkAppKey = PrivateKey.fromBase58(zkAppPrivateKey!);
    const zkAppAddress = zkAppKey.toPublicKey();
    console.log(`   zkApp address: ${zkAppAddress.toBase58()}`);
    console.log();

    // Save deployment info
    const deploymentInfo: {
      network: string;
      zkAppAddress: string;
      payerAddress: string;
      adminAddress: string; // admin is set to deployer during init()
      deployedAt: string;
      explorerUrl: string;
      txHash?: string;
    } = {
      network: networkName,
      zkAppAddress: zkAppAddress.toBase58(),
      payerAddress: payerPublicKey.toBase58(),
      adminAddress: payerPublicKey.toBase58(),
      deployedAt: new Date().toISOString(),
      explorerUrl: `${network.explorer}/account/${zkAppAddress.toBase58()}`,
    };

    const deploymentsDir = './deployments';
    if (!fs.existsSync(deploymentsDir)) {
      fs.mkdirSync(deploymentsDir);
    }

    const deploymentFile = path.join(
      deploymentsDir,
      `${networkName}-deployment.json`
    );
    fs.writeFileSync(deploymentFile, JSON.stringify(deploymentInfo, null, 2));
    console.log(`💾 Deployment info saved to ${deploymentFile}\n`);

    // Create zkApp instance first (needed for BatchReducer)
    const zkApp = new AuthenticityZkApp(zkAppAddress);

    // Set contract instance for BatchReducer before compilation
    console.log('🔧 Setting up BatchReducer with contract instance...');
    BatchReducerUtils.setContractInstance(zkApp);
    console.log('✅ BatchReducer configured\n');

    // Import and compile AuthenticityProgram first (dependency)
    console.log('🔨 Compiling AuthenticityProgram (dependency)...');
    const { AuthenticityProgram } = await import('./AuthenticityProof.js');
    const programCompileStartTime = Date.now();
    await AuthenticityProgram.compile();
    const programCompileTime = (
      (Date.now() - programCompileStartTime) /
      1000
    ).toFixed(1);
    console.log(`✅ AuthenticityProgram compiled in ${programCompileTime}s\n`);

    // Compile BatchReducer
    console.log('🔨 Compiling BatchReducer...');
    const batchReducerCompileStartTime = Date.now();
    await BatchReducerUtils.compile();
    const batchReducerCompileTime = (
      (Date.now() - batchReducerCompileStartTime) /
      1000
    ).toFixed(1);
    console.log(`✅ BatchReducer compiled in ${batchReducerCompileTime}s\n`);

    // Compile the contract
    console.log('🔨 Compiling AuthenticityZkApp...');
    const compileStartTime = Date.now();
    await AuthenticityZkApp.compile();
    const compileTime = ((Date.now() - compileStartTime) / 1000).toFixed(1);
    console.log(`✅ Contract compiled in ${compileTime}s\n`);

    // Create deployment transaction
    console.log('📝 Creating deployment transaction...');
    const deployTxn = await Mina.transaction(
      { sender: payerPublicKey, fee: 0.1e9 }, // 0.1 MINA fee
      async () => {
        AccountUpdate.fundNewAccount(payerPublicKey);
        await zkApp.deploy();
      }
    );

    // Prove the transaction
    console.log('🧮 Generating deployment proof...');
    const proveStartTime = Date.now();
    await deployTxn.prove();
    const proveTime = ((Date.now() - proveStartTime) / 1000).toFixed(1);
    console.log(`✅ Proof generated in ${proveTime}s\n`);

    // Sign and send the transaction
    console.log('📤 Signing and sending transaction...');
    const signedTxn = deployTxn.sign([payerKey, zkAppKey]);
    const txnResult = await signedTxn.send();

    if (txnResult.status === 'pending') {
      console.log('✅ Transaction sent successfully!');
      console.log(`   Transaction hash: ${txnResult.hash}`);
      console.log(
        `   View on explorer: ${network.explorer}/transaction/${txnResult.hash}\n`
      );
      console.log('⏳ Waiting for transaction to be included in a block...');
      console.log('   This may take a few minutes.\n');

      // Update deployment info with transaction hash
      deploymentInfo.txHash = txnResult.hash;
      fs.writeFileSync(deploymentFile, JSON.stringify(deploymentInfo, null, 2));

      console.log('🎉 Deployment complete!');
      console.log(`   zkApp address: ${zkAppAddress.toBase58()}`);
      console.log(`   Admin address: ${deploymentInfo.adminAddress}`);
      console.log(`   Explorer: ${deploymentInfo.explorerUrl}`);
    } else {
      console.error('❌ Transaction failed:', txnResult);
    }
  } catch (error) {
    console.error('❌ Deployment failed:', error);
    process.exit(1);
  }
}

// Run deployment
deploy().catch((error) => {
  console.error('❌ Unexpected error:', error);
  process.exit(1);
});
