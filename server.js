import "dotenv/config";
import express from "express";

import crypto from "crypto";
import { crc32 } from "crc";  // <-- updated import

import fs from "fs/promises";
import fetch from "node-fetch";

const {
  LISTEN_PORT = 8888,
  LISTEN_PATH = "/",
  CACHE_DIR = ".",
  WEBHOOK_ID = "<your-webhook-id-here>",
} = process.env;

async function downloadAndCache(url, cacheKey) {
  if (!cacheKey) {
    cacheKey = url.replace(/\W+/g, "-");
  }
  const filePath = `${CACHE_DIR}/${cacheKey}`;

  // Check if cached file exists
  const cachedData = await fs.readFile(filePath, "utf-8").catch(() => null);
  if (cachedData) {
    return cachedData;
  }

  // Download the file if not cached
  const response = await fetch(url);
  const data = await response.text();
  await fs.writeFile(filePath, data);

  return data;
}

const app = express();

app.post(LISTEN_PATH, express.raw({ type: "application/json" }), async (request, response) => {
  const headers = request.headers;
  const event = request.body.toString(); // raw body as string
  const data = JSON.parse(event);

  console.log(`headers`, headers);
  console.log(`parsed json`, JSON.stringify(data, null, 2));
  console.log(`raw event: ${event}`);

  const isSignatureValid = await verifySignature(event, headers);

  if (isSignatureValid) {
    console.log("Signature is valid.");

    // Process webhook data here
    console.log("Received event", JSON.stringify(data, null, 2));
  } else {
    console.log(`Signature is not valid for ${data?.id} ${headers?.["correlation-id"]}`);
  }

  response.sendStatus(200);
});

async function verifySignature(event, headers) {
  const transmissionId = headers["paypal-transmission-id"];
  const timeStamp = headers["paypal-transmission-time"];
  // Use crc32 from 'crc' - it returns a number
  const crc = crc32(event);

  const message = `${transmissionId}|${timeStamp}|${WEBHOOK_ID}|${crc}`;
  console.log(`Original signed message: ${message}`);

  const certPem = await downloadAndCache(headers["paypal-cert-url"]);

  // Base64 signature buffer
  const signatureBuffer = Buffer.from(headers["paypal-transmission-sig"], "base64");

  const verifier = crypto.createVerify("SHA256");
  verifier.update(message);

  return verifier.verify(certPem, signatureBuffer);
}

app.listen(LISTEN_PORT, () => {
  console.log(`Node server listening at http://localhost:${LISTEN_PORT}/`);
});
