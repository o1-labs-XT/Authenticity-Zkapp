import sharp from 'sharp';
import crypto from 'crypto';
import { Bytes32 } from './commitmentHelpers.js';
import { Field } from 'o1js';

/**
 * Pixel-based image hashing for metadata-independent authenticity verification.
 * This ensures that images with the same visual content produce the same commitment,
 * regardless of metadata changes.
 */

export interface PixelHashOptions {
  // Whether to normalize the image format before hashing
  normalizeFormat?: boolean;
  // Target format for normalization (if enabled)
  targetFormat?: 'png' | 'jpeg';
  // JPEG quality if converting to JPEG
  jpegQuality?: number;
}

/**
 * Extracts and hashes pixel data from an image, ignoring metadata
 * @param imageData - The image data as a Buffer
 * @param options - Options for pixel extraction
 * @returns SHA-256 hash of the pixel data
 */
export async function hashImagePixels(
  imageData: Buffer,
  options: PixelHashOptions = {}
): Promise<string> {
  const {
    normalizeFormat = false,
    targetFormat = 'png',
    jpegQuality = 95
  } = options;

  let imageProcessor = sharp(imageData);
  
  // Optionally normalize format
  if (normalizeFormat) {
    if (targetFormat === 'jpeg') {
      imageProcessor = imageProcessor.jpeg({ quality: jpegQuality });
    } else {
      imageProcessor = imageProcessor.png();
    }
  }
  
  // Extract raw pixel data
  const { data: pixelData, info } = await imageProcessor
    .raw()
    .ensureAlpha() // Ensure consistent 4-channel RGBA
    .toBuffer({ resolveWithObject: true });
  
  // Create hash including dimensions
  const hash = crypto.createHash('sha256');
  
  // Include image dimensions and channel count
  const dimensionString = `${info.width}:${info.height}:${info.channels}:`;
  hash.update(Buffer.from(dimensionString));
  
  // Add pixel data
  hash.update(pixelData);
  
  return hash.digest('hex');
}

/**
 * Computes on-chain commitment for pixel data
 * @param imageData - The image data as a Buffer
 * @param options - Options for pixel extraction
 * @returns The SHA-256 hash and Bytes32 representation
 */
export async function computePixelBasedCommitment(
  imageData: Buffer,
  options: PixelHashOptions = {}
): Promise<{
  sha256: string;
  bytes32: Bytes32;
  fields: Field[];
}> {
  // Get pixel-based hash
  const sha256Hash = await hashImagePixels(imageData, options);
  
  // Convert to Bytes32
  const bytes32 = Bytes32.fromHex(sha256Hash);
  
  // Get field representation for on-chain storage
  const fields = bytes32.toFields();
  
  return {
    sha256: sha256Hash,
    bytes32,
    fields,
  };
}

/**
 * Verifies if two images have the same visual content
 * @param imageData1 - First image data
 * @param imageData2 - Second image data
 * @param options - Options for pixel extraction
 * @returns True if images have identical pixel content
 */
export async function verifyPixelEquality(
  imageData1: Buffer,
  imageData2: Buffer,
  options: PixelHashOptions = {}
): Promise<boolean> {
  const hash1 = await hashImagePixels(imageData1, options);
  const hash2 = await hashImagePixels(imageData2, options);
  return hash1 === hash2;
}

/**
 * Computes a simple perceptual hash for fuzzy matching
 * @param imageData - The image data as a Buffer
 * @returns A perceptual hash string
 */
export async function computePerceptualHash(imageData: Buffer): Promise<string> {
  // Resize to 8x8 grayscale for simple perceptual hashing
  const size = 8;
  
  const { data } = await sharp(imageData)
    .grayscale()
    .resize(size, size, { 
      fit: 'fill',
      kernel: 'lanczos3' // Better quality downsampling
    })
    .raw()
    .toBuffer({ resolveWithObject: true });
  
  // Compute average brightness
  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    sum += data[i];
  }
  const avg = sum / data.length;
  
  // Create binary hash based on pixels above/below average
  let hash = BigInt(0);
  for (let i = 0; i < data.length; i++) {
    if (data[i] > avg) {
      hash |= BigInt(1) << BigInt(i);
    }
  }
  
  return hash.toString(16).padStart(16, '0');
}

/**
 * Computes Hamming distance between two perceptual hashes
 * @param hash1 - First perceptual hash
 * @param hash2 - Second perceptual hash
 * @returns Number of differing bits
 */
export function perceptualHashDistance(hash1: string, hash2: string): number {
  const n1 = BigInt('0x' + hash1);
  const n2 = BigInt('0x' + hash2);
  let xor = n1 ^ n2;
  
  // Count set bits (Hamming weight)
  let distance = 0;
  while (xor > 0n) {
    distance += Number(xor & 1n);
    xor >>= 1n;
  }
  
  return distance;
}

/**
 * Checks if two images are visually similar based on perceptual hashing
 * @param imageData1 - First image data
 * @param imageData2 - Second image data
 * @param threshold - Maximum Hamming distance to consider similar (default: 5)
 * @returns True if images are visually similar
 */
export async function areImagesSimilar(
  imageData1: Buffer,
  imageData2: Buffer,
  threshold = 5
): Promise<boolean> {
  const hash1 = await computePerceptualHash(imageData1);
  const hash2 = await computePerceptualHash(imageData2);
  const distance = perceptualHashDistance(hash1, hash2);
  return distance <= threshold;
}