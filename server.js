import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { crc32 } from "crc";
import fs from "fs/promises";
import fetch from "node-fetch";

const {
  LISTEN_PORT = 8888,
  LISTEN_PATH = "/",
  CACHE_DIR = ".",
  WEBHOOK_ID = "<your-webhook-id-here>", // Replace this with your actual PayPal webhook ID
} = process.env;

async function downloadAndCache(url, cacheKey) {
  if (!cacheKey) {
    cacheKey = url.replace(/\W+/g, "-");
  }
  const filePath = `${CACHE_DIR}/${cacheKey}`;

  const cachedData = await fs.readFile(filePath, "utf-8").catch(() => null);
  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(url);
  const data = await response.text();
  await fs.writeFile(filePath, data);

  return data;
}

const app = express();

app.post(LISTEN_PATH, express.raw({ type: "application/json" }), async (request, response) => {
  const headers = request.headers;
  const event = request.body.toString(); // raw body as string

  let data;
  try {
    data = JSON.parse(event);
  } catch (err) {
    console.error("Failed to parse JSON event:", err);
    return response.sendStatus(400);
  }

  console.log(`headers`, headers);
  console.log(`parsed json`, JSON.stringify(data, null, 2));
  console.log(`raw event: ${event}`);

  const isSignatureValid = await verifySignature(event, headers);

  if (isSignatureValid) {
    console.log("Signature is valid.");
    // Process your webhook data here
    console.log("Received event", JSON.stringify(data, null, 2));
  } else {
    console.log(`Signature is not valid for ${data?.id} ${headers?.["correlation-id"]}`);
  }

  response.sendStatus(200);
});

async function verifySignature(event, headers) {
  const transmissionId = headers["paypal-transmission-id"];
  const timeStamp = headers["paypal-transmission-time"];
  const certUrl = headers["paypal-cert-url"];
  const signature = headers["paypal-transmission-sig"];

  if (!transmissionId || !timeStamp || !certUrl || !signature) {
    console.error("Missing required PayPal headers for signature verification");
    return false;
  }

  // Convert CRC32 to unsigned decimal string
  const crc = (crc32(event) >>> 0).toString();

  const message = `${transmissionId}|${timeStamp}|${WEBHOOK_ID}|${crc}`;
  console.log(`Original signed message: ${message}`);

  // Download and cache the PayPal public certificate
  const certPem = await downloadAndCache(certUrl);

  // Decode the signature from base64
  const signatureBuffer = Buffer.from(signature, "base64");

  const verifier = crypto.createVerify("SHA256");
  verifier.update(message);

  try {
    return verifier.verify(certPem, signatureBuffer);
  } catch (err) {
    console.error("Error during signature verification:", err);
    return false;
  }
}

app.listen(LISTEN_PORT, () => {
  console.log(`Node server listening at http://localhost:${LISTEN_PORT}/`);
});
