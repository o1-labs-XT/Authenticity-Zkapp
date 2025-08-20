import { UInt32, Bytes, Struct, Provable } from 'o1js';
let crypto: typeof import('crypto') | undefined;
let fs: typeof import('fs') | undefined;

if (
  typeof process !== 'undefined' &&
  process.versions &&
  process.versions.node
) {
  crypto = await import('crypto');
  fs = await import('fs');
}

export {
  Bytes32,
  FinalRoundInputs,
  hashUntilFinalRound,
  performFinalSHA256Round,
  hashImageOffCircuit,
  prepareImageVerification,
  computeOnChainCommitment,
};

class Bytes32 extends Bytes(32) {}

class FinalRoundInputs extends Struct({
  state: Provable.Array(UInt32, 8), // 256 bits = 8 * 32 bits
  initialState: Provable.Array(UInt32, 8),
  messageWord: UInt32,
  roundConstant: UInt32,
}) {}

// SHA-256 constants
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Initial hash values for SHA-256
const INITIAL_HASH = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19,
];

/**
 * Computes SHA-256 hash of image data outside the circuit
 * @param {Buffer} imageData - The image data to hash
 * @returns {string} - The SHA-256 hash as hex string
 */
function hashImageOffCircuit(imageData: Buffer): string {
  if (!crypto) {
    throw new Error('Crypto module is not available in this environment');
  }
  return crypto.createHash('sha256').update(imageData).digest('hex');
}

/**
 * Performs SHA-256 hashing up to but not including the final round
 * @param imageData - The image data to hash
 * @returns Object containing the state before final round and final round inputs
 */
function hashUntilFinalRound(imageData: Buffer) {
  // Get the complete SHA-256 hash for verification
  const expectedHash = hashImageOffCircuit(imageData);

  // Pad the message according to SHA-256 specification
  const paddedData = padSHA256Message(imageData);

  // Process all blocks except perform all rounds except the final one on the last block
  let state = [...INITIAL_HASH];

  // Split into 512-bit (64-byte) blocks
  const blocks: Buffer[] = [];
  for (let i = 0; i < paddedData.length; i += 64) {
    blocks.push(paddedData.subarray(i, i + 64));
  }

  // Process all blocks except the last one completely
  for (let blockIndex = 0; blockIndex < blocks.length - 1; blockIndex++) {
    state = processSHA256Block(state, blocks[blockIndex]);
  }

  // Process the final block up to round 62 (leaving round 63 for the circuit)
  const finalBlock = blocks[blocks.length - 1];
  const { penultimateState, finalRoundInputs } =
    processFinalBlockUntilLastRound(state, finalBlock);

  return {
    penultimateState,
    finalRoundInputs,
    expectedHash,
  };
}

/**
 * Pads message according to SHA-256 specification
 */
function padSHA256Message(data: Buffer): Buffer {
  const messageLength = data.length;
  const messageLengthBits = messageLength * 8;

  // Calculate padded length (multiple of 64 bytes)
  const paddedLength = Math.ceil((messageLength + 9) / 64) * 64;
  const padded = Buffer.alloc(paddedLength);

  // Copy original data
  data.copy(padded, 0);

  // Add padding bit (0x80)
  padded[messageLength] = 0x80;

  // Add length as 64-bit big-endian integer at the end
  padded.writeBigUInt64BE(BigInt(messageLengthBits), paddedLength - 8);

  return padded;
}

/**
 * Processes a complete SHA-256 block (all 64 rounds)
 */
function processSHA256Block(state: number[], block: Buffer): number[] {
  const w = new Array(64);

  // Prepare message schedule
  for (let i = 0; i < 16; i++) {
    w[i] = block.readUInt32BE(i * 4);
  }

  for (let i = 16; i < 64; i++) {
    const s0 =
      rightRotate(w[i - 15], 7) ^
      rightRotate(w[i - 15], 18) ^
      (w[i - 15] >>> 3);
    const s1 =
      rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }

  // Initialize working variables
  let [a, b, c, d, e, f, g, h] = state;

  // Perform all 64 rounds
  for (let i = 0; i < 64; i++) {
    const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
    const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  // Add this chunk's hash to result
  return [
    (state[0] + a) >>> 0,
    (state[1] + b) >>> 0,
    (state[2] + c) >>> 0,
    (state[3] + d) >>> 0,
    (state[4] + e) >>> 0,
    (state[5] + f) >>> 0,
    (state[6] + g) >>> 0,
    (state[7] + h) >>> 0,
  ];
}

/**
 * Processes the final block up to round 62, leaving round 63 for the circuit
 */
function processFinalBlockUntilLastRound(state: number[], block: Buffer) {
  const w = new Array(64);

  // Prepare message schedule
  for (let i = 0; i < 16; i++) {
    w[i] = block.readUInt32BE(i * 4);
  }

  for (let i = 16; i < 64; i++) {
    const s0 =
      rightRotate(w[i - 15], 7) ^
      rightRotate(w[i - 15], 18) ^
      (w[i - 15] >>> 3);
    const s1 =
      rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }

  // Initialize working variables
  let [a, b, c, d, e, f, g, h] = state;

  // Perform 63 rounds (stopping before the final round)
  for (let i = 0; i < 63; i++) {
    const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
    const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  return {
    penultimateState: [a, b, c, d, e, f, g, h],
    finalRoundInputs: {
      initialState: state,
      messageWord: w[63],
      roundConstant: K[63],
    },
  };
}

function performFinalSHA256Round(
  state: [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32],
  initialState: [
    UInt32,
    UInt32,
    UInt32,
    UInt32,
    UInt32,
    UInt32,
    UInt32,
    UInt32
  ],
  messageWord: UInt32,
  roundConstant: UInt32
): [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32] {
  let [a, b, c, d, e, f, g, h] = state;

  // Perform round 63
  const S1 = rightRotate32(e, 6)
    .xor(rightRotate32(e, 11))
    .xor(rightRotate32(e, 25));

  const ch = e.and(f).xor(e.not().and(g));

  // Use modular addition to handle overflow
  let temp1 = h.addMod32(S1);
  temp1 = temp1.addMod32(ch);
  temp1 = temp1.addMod32(roundConstant);
  temp1 = temp1.addMod32(messageWord);

  const S0 = rightRotate32(a, 2)
    .xor(rightRotate32(a, 13))
    .xor(rightRotate32(a, 22));

  const maj = a.and(b).xor(a.and(c)).xor(b.and(c));
  const temp2 = S0.addMod32(maj);

  // Update working variables
  h = g;
  g = f;
  f = e;
  e = d.addMod32(temp1);
  d = c;
  c = b;
  b = a;
  a = temp1.addMod32(temp2);

  // Add to initial state to get final hash using modular addition
  return [
    initialState[0].addMod32(a),
    initialState[1].addMod32(b),
    initialState[2].addMod32(c),
    initialState[3].addMod32(d),
    initialState[4].addMod32(e),
    initialState[5].addMod32(f),
    initialState[6].addMod32(g),
    initialState[7].addMod32(h),
  ];
}

function rightRotate(value: number, amount: number): number {
  return ((value >>> amount) | (value << (32 - amount))) >>> 0;
}

function rightRotate32(value: UInt32, bits: number): UInt32 {
  const shifted = value.rightShift(bits);
  const rotated = value.leftShift(32 - bits);
  return shifted.or(rotated);
}

/**
 * Prepares inputs for the circuit verification
 * @param imagePath - Path to the image file
 * @returns Object containing all circuit inputs
 */
function prepareImageVerification(imagePath: string) {
  if (!fs) {
    throw new Error('File system module is not available in this environment');
  }
  const imageData = fs.readFileSync(imagePath);
  const { penultimateState, finalRoundInputs, expectedHash } =
    hashUntilFinalRound(imageData);

  console.log('Image size:', imageData.length, 'bytes');
  console.log('Expected SHA-256 hash:', expectedHash);

  // Convert to o1js types
  const penultimateStateUInt32 = penultimateState.map((x) =>
    UInt32.from(x)
  ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
  const initialStateUInt32 = finalRoundInputs.initialState.map((x) =>
    UInt32.from(x)
  ) as [UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32];
  const messageWord = UInt32.from(finalRoundInputs.messageWord);
  const roundConstant = UInt32.from(finalRoundInputs.roundConstant);
  const expectedHashBytes = Bytes32.fromHex(expectedHash);

  return {
    penultimateState: penultimateStateUInt32,
    initialState: initialStateUInt32,
    messageWord,
    roundConstant,
    expectedHash: expectedHashBytes,
    expectedHashHex: expectedHash,
  };
}

/**
 * Computes the on-chain commitment value for an image
 * This is the exact value that will be stored in the smart contract
 * @param imageData - The image data as a Buffer
 * @returns The SHA-256 hash and its two field representation
 */
async function computeOnChainCommitment(imageData: Buffer) {
  // Compute SHA-256 hash using hashImageOffCircuit
  const sha256Hash = hashImageOffCircuit(imageData);

  // Convert to Bytes32
  const bytes32 = Bytes32.fromHex(sha256Hash);

  // import SHACommitment from AuthenticityZkApp here to avoid circular dependency
  const { SHACommitment } = await import('./AuthenticityZkApp.js');

  // Create SHACommitment and get the two fields
  const shaCommitment = new SHACommitment({ bytes: bytes32 });
  const { high128, low128 } = shaCommitment.toTwoFields();

  return {
    sha256: sha256Hash,
    high128,
    low128,
  };
}
