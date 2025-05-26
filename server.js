// server.js
import "dotenv/config";
import express from "express";
import crypto from "crypto";
import crc32 from "buffer-crc32";
import fs from "fs/promises";
import fetch from "node-fetch";

const {
  LISTEN_PORT = 8888,
  LISTEN_PATH = "/",
  CACHE_DIR = ".",
  WEBHOOK_ID,
} = process.env;
if (!WEBHOOK_ID) {
  console.error('Missing WEBHOOK_ID in environment');
  process.exit(1);
}

async function downloadAndCache(url, cacheKey) {
  cacheKey = cacheKey || url.replace(/\W+/g, '-');
  const filePath = `${CACHE_DIR}/${cacheKey}`;
  const cached = await fs.readFile(filePath, 'utf8').catch(() => null);
  if (cached) return cached;
  const res = await fetch(url);
  const data = await res.text();
  await fs.writeFile(filePath, data);
  return data;
}

const app = express();
app.post(LISTEN_PATH, express.raw({ type: 'application/json' }), async (req, res) => {
  const headers = req.headers;
  const raw = req.body.toString('utf8');
  console.log('Headers:', headers);
  console.log('Raw payload:', raw);
  const data = JSON.parse(raw);

  const valid = await verifySignature(raw, headers);
  if (!valid) {
    console.error('Invalid signature for event', data.id);
    return res.sendStatus(400);
  }
  console.log('✔️ Signature valid, processing event', data.id);
  // TODO: handle event
  res.sendStatus(200);
});

async function verifySignature(rawEvent, headers) {
  const id = headers['paypal-transmission-id'];
  const time = headers['paypal-transmission-time'];
  const crc = parseInt("0x" + crc32(rawEvent).toString('hex'));
  const message = `${id}|${time}|${WEBHOOK_ID}|${crc}`;
  console.log('Signed message:', message);
  const cert = await downloadAndCache(headers['paypal-cert-url']);
  const sig = Buffer.from(headers['paypal-transmission-sig'], 'base64');
  const verifier = crypto.createVerify('SHA256');
  verifier.update(message);
  return verifier.verify(cert, sig);
}

app.listen(LISTEN_PORT, () => console.log(`Listening on port ${LISTEN_PORT}`));
