import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import {
  hashImagePixels,
  computePixelBasedCommitment,
  verifyPixelEquality,
  computePerceptualHash,
  perceptualHashDistance,
  areImagesSimilar
} from './pixelBasedAuthenticity.js';

describe('Pixel-based authenticity', () => {
  const catImagePath = './example/cat.png';
  const catNoMetaPath = './example/cat_no_meta.png';
  
  // Only run tests if example images exist
  const skipTests = !fs.existsSync(catImagePath) || !fs.existsSync(catNoMetaPath);
  
  it('should produce identical hashes for images with same pixels but different metadata', async (t) => {
    if (skipTests) {
      t.skip('Example images not found');
      return;
    }
    
    const catImage = fs.readFileSync(catImagePath);
    const catNoMeta = fs.readFileSync(catNoMetaPath);
    
    // File hashes should be different (due to metadata)
    const crypto = await import('crypto');
    const fileHash1 = crypto.createHash('sha256').update(catImage).digest('hex');
    const fileHash2 = crypto.createHash('sha256').update(catNoMeta).digest('hex');
    assert.notStrictEqual(fileHash1, fileHash2, 'File hashes should differ');
    
    // Pixel hashes should be identical
    const pixelHash1 = await hashImagePixels(catImage);
    const pixelHash2 = await hashImagePixels(catNoMeta);
    assert.strictEqual(pixelHash1, pixelHash2, 'Pixel hashes should match');
    
    console.log('✅ Pixel hashing correctly ignores metadata');
  });

  it('should verify pixel equality correctly', async (t) => {
    if (skipTests) {
      t.skip('Example images not found');
      return;
    }
    
    const catImage = fs.readFileSync(catImagePath);
    const catNoMeta = fs.readFileSync(catNoMetaPath);
    
    const areEqual = await verifyPixelEquality(catImage, catNoMeta);
    assert.strictEqual(areEqual, true, 'Images should have equal pixels');
    
    console.log('✅ Pixel equality verification works');
  });

  it('should compute consistent on-chain commitments for pixel data', async (t) => {
    if (skipTests) {
      t.skip('Example images not found');
      return;
    }
    
    const catImage = fs.readFileSync(catImagePath);
    const catNoMeta = fs.readFileSync(catNoMetaPath);
    
    const commitment1 = await computePixelBasedCommitment(catImage);
    const commitment2 = await computePixelBasedCommitment(catNoMeta);
    
    assert.strictEqual(commitment1.sha256, commitment2.sha256);
    assert.strictEqual(commitment1.bytes32.toHex(), commitment2.bytes32.toHex());
    
    // Compare field representations
    assert.strictEqual(commitment1.fields.length, commitment2.fields.length);
    for (let i = 0; i < commitment1.fields.length; i++) {
      assert.strictEqual(
        commitment1.fields[i].toBigInt().toString(),
        commitment2.fields[i].toBigInt().toString()
      );
    }
    
    console.log('✅ On-chain commitments are consistent');
    console.log(`   SHA-256: ${commitment1.sha256}`);
    console.log(`   Bytes32: ${commitment1.bytes32.toHex()}`);
    console.log(`   Fields: ${commitment1.fields.length} field(s)`);
  });

  it('should compute identical perceptual hashes for same content', async (t) => {
    if (skipTests) {
      t.skip('Example images not found');
      return;
    }
    
    const catImage = fs.readFileSync(catImagePath);
    const catNoMeta = fs.readFileSync(catNoMetaPath);
    
    const pHash1 = await computePerceptualHash(catImage);
    const pHash2 = await computePerceptualHash(catNoMeta);
    
    assert.strictEqual(pHash1, pHash2, 'Perceptual hashes should match');
    
    const distance = perceptualHashDistance(pHash1, pHash2);
    assert.strictEqual(distance, 0, 'Hamming distance should be 0');
    
    console.log('✅ Perceptual hashing works');
    console.log(`   Hash: ${pHash1}`);
  });

  it('should correctly identify similar images', async (t) => {
    if (skipTests) {
      t.skip('Example images not found');
      return;
    }
    
    const catImage = fs.readFileSync(catImagePath);
    const catNoMeta = fs.readFileSync(catNoMetaPath);
    
    const similar = await areImagesSimilar(catImage, catNoMeta);
    assert.strictEqual(similar, true, 'Images should be identified as similar');
    
    console.log('✅ Image similarity detection works');
  });

  it('should produce consistent hashes regardless of input format', async (t) => {
    if (skipTests) {
      t.skip('Example images not found');
      return;
    }
    
    const catImage = fs.readFileSync(catImagePath);
    
    // Test that normalization doesn't affect pixel hashes
    // (since we're extracting raw pixels regardless of format)
    const hashDefault = await hashImagePixels(catImage);
    const hashNormalized = await hashImagePixels(catImage, { 
      normalizeFormat: true, 
      targetFormat: 'png' 
    });
    
    // Raw pixel data should be the same regardless of normalization settings
    assert.strictEqual(hashDefault, hashNormalized, 
      'Pixel hashes should be identical regardless of normalization');
    
    console.log('✅ Pixel extraction is format-independent');
    console.log(`   Hash: ${hashDefault}`);
  });
});