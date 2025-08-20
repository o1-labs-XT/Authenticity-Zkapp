#!/usr/bin/env npx tsx

/**
 * Demo script showing how pixel-based hashing can be used for 
 * metadata-independent image authenticity verification
 */

import fs from 'fs';
import {
  hashImagePixels,
  computePixelBasedCommitment,
  verifyPixelEquality,
  computePerceptualHash,
  areImagesSimilar
} from '../src/pixelBasedAuthenticity.js';

async function main() {
  console.log('🎨 Pixel-Based Image Authenticity Demo\n');
  
  const images = {
    original: './example/cat.png',
    noMeta: './example/cat_no_meta.png'
  };
  
  // 1. Show file-based vs pixel-based hashing
  console.log('📊 Comparing File Hashes vs Pixel Hashes:\n');
  
  for (const [name, path] of Object.entries(images)) {
    const imageData = fs.readFileSync(path);
    
    // Traditional file hash (includes metadata)
    const crypto = await import('crypto');
    const fileHash = crypto.createHash('sha256').update(imageData).digest('hex');
    
    // Pixel-based hash (excludes metadata)
    const pixelHash = await hashImagePixels(imageData);
    
    console.log(`${name}:`);
    console.log(`  File hash:  ${fileHash}`);
    console.log(`  Pixel hash: ${pixelHash}\n`);
  }
  
  // 2. Demonstrate pixel equality verification
  console.log('🔍 Verifying Pixel Equality:\n');
  
  const img1 = fs.readFileSync(images.original);
  const img2 = fs.readFileSync(images.noMeta);
  
  const areEqual = await verifyPixelEquality(img1, img2);
  console.log(`Images have identical pixels: ${areEqual ? '✅ YES' : '❌ NO'}\n`);
  
  // 3. Show on-chain commitment computation
  console.log('⛓️ Computing On-Chain Commitments:\n');
  
  const commitment = await computePixelBasedCommitment(img1);
  console.log(`SHA-256: ${commitment.sha256}`);
  console.log(`Bytes32: ${commitment.bytes32.toHex()}`);
  console.log(`Fields:  ${commitment.fields.length} field(s) for on-chain storage\n`);
  
  // 4. Demonstrate perceptual hashing
  console.log('👁️ Perceptual Hashing (for fuzzy matching):\n');
  
  const pHash1 = await computePerceptualHash(img1);
  const pHash2 = await computePerceptualHash(img2);
  
  console.log(`Original:   ${pHash1}`);
  console.log(`No Meta:    ${pHash2}`);
  console.log(`Similar:    ${await areImagesSimilar(img1, img2) ? '✅ YES' : '❌ NO'}\n`);
  
  // 5. Usage recommendations
  console.log('💡 Usage Recommendations:\n');
  console.log('• Use pixel hashing when you want to verify image content regardless of metadata');
  console.log('• Use perceptual hashing to detect similar (but not identical) images');
  console.log('• Store pixel-based commitments on-chain for true content verification');
  console.log('• Consider normalizing format for cross-format comparisons\n');
  
  console.log('✨ Demo complete!');
}

main().catch(console.error);