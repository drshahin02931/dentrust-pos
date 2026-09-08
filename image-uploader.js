'use strict';

const sharp = require('sharp');
const ftp = require('basic-ftp');
const { Readable } = require('stream');

const FTP_CONFIG = {
  host: process.env.FTP_HOST || '147.93.88.36',
  user: process.env.FTP_USER || 'u997051991',
  password: process.env.FTP_PASSWORD || 'Is255205@ok#',
  port: parseInt(process.env.FTP_PORT || '21', 10),
  secure: false
};

const REMOTE_DIR = '/domains/dentrust.site/public_html/products_opt';

/**
 * Converts any image source (Buffer, base64 data-URL, or HTTP URL) to an optimized WebP Buffer.
 */
async function toOptimizedWebP(imageInput) {
  let inputBuffer = null;

  if (Buffer.isBuffer(imageInput)) {
    inputBuffer = imageInput;
  } else if (typeof imageInput === 'string') {
    if (imageInput.startsWith('data:')) {
      const match = imageInput.match(/^data:[^;]+;base64,(.+)$/);
      if (match) {
        inputBuffer = Buffer.from(match[1], 'base64');
      } else {
        throw new Error('Invalid base64 data URL');
      }
    } else if (imageInput.startsWith('http://') || imageInput.startsWith('https://')) {
      const res = await fetch(imageInput);
      if (!res.ok) throw new Error(`Failed to fetch image from URL: ${res.statusText}`);
      const ab = await res.arrayBuffer();
      inputBuffer = Buffer.from(ab);
    } else {
      throw new Error('Unsupported image format string');
    }
  } else {
    throw new Error('Invalid imageInput provided');
  }

  // Optimize with Sharp: Max 600x600, quality 82 WebP
  return sharp(inputBuffer)
    .resize(600, 600, { fit: 'inside', withoutEnlargement: true })
    .webp({ quality: 82, effort: 4 })
    .toBuffer();
}

/**
 * Uploads a WebP buffer directly to Hostinger FTP for a specific product ID.
 */
async function uploadToHostingerFtp(productId, webpBuffer) {
  const client = new ftp.Client();
  client.ftp.verbose = false;
  client.ftp.timeout = 30000;

  try {
    await client.access(FTP_CONFIG);
    await client.ensureDir(REMOTE_DIR);

    const stream = Readable.from(webpBuffer);
    const remoteFilename = `${productId}.webp`;
    await client.uploadFrom(stream, remoteFilename);

    const publicUrl = `https://dentrust.site/products_opt/${remoteFilename}`;
    console.log(`[ImageUploader] Successfully uploaded ${remoteFilename} to Hostinger (${webpBuffer.length} bytes)`);
    return publicUrl;
  } finally {
    client.close();
  }
}

/**
 * Main function: Process, upload to Hostinger, and update DB in background.
 */
async function processAndUploadProductImage(productId, imageInput, posDb, dentrustDb) {
  if (!productId || !imageInput) return null;

  try {
    const webpBuf = await toOptimizedWebP(imageInput);
    const publicUrl = await uploadToHostingerFtp(productId, webpBuf);

    if (posDb) {
      await posDb.query(
        `UPDATE products SET image_url = $1 WHERE id = $2`,
        [publicUrl, productId]
      ).catch(e => console.error('[ImageUploader] posDb update failed:', e.message));

      // Also ensure photos array in public.products contains this image as primary
      try {
        const { rows: [p] } = await posDb.query('SELECT photos, dentrust_id FROM public.products WHERE id=$1', [productId]);
        let photos = Array.isArray(p?.photos) ? p.photos : [];
        if (!photos.includes(publicUrl)) {
          photos = [publicUrl, ...photos].slice(0, 5);
          await posDb.query('UPDATE public.products SET photos=$1 WHERE id=$2', [photos, productId]);
        }

        // Sync to website DB if linked
        if (dentrustDb && p?.dentrust_id) {
          const dtClient = await dentrustDb.connect();
          try {
            await dtClient.query(
              'UPDATE products SET photos=$1 WHERE id=$2',
              [JSON.stringify(photos), p.dentrust_id]
            );
          } finally {
            dtClient.release();
          }
        }
      } catch (syncErr) {
        console.warn('[ImageUploader] sync photos warning:', syncErr.message);
      }
    }

    return publicUrl;
  } catch (err) {
    console.error(`[ImageUploader] Error processing image for product #${productId}:`, err.message);
    return null;
  }
}

module.exports = {
  toOptimizedWebP,
  uploadToHostingerFtp,
  processAndUploadProductImage
};
