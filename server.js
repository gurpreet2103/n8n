const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 8888;

const PAYPAL_WEBHOOK_ID = 'WH-54M31324A08453805-0TT498265C515724R'; // Replace with your actual webhook ID

// Capture raw body for signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.post('/', async (req, res) => {
  console.log('headers', req.headers);
  console.log('parsed json', req.body);

  const transmissionId = req.headers['paypal-transmission-id'];
  const transmissionTime = req.headers['paypal-transmission-time'];
  const certUrl = req.headers['paypal-cert-url'];
  const authAlgo = req.headers['paypal-auth-algo'];
  const transmissionSig = req.headers['paypal-transmission-sig'];
  const webhookEventBody = req.rawBody;

  // Step 1: Download PayPal cert
  try {
    const { data: certPem } = await axios.get(certUrl);
    
    // Step 2: Build expected signature string
    const expectedSig = `${transmissionId}|${transmissionTime}|${PAYPAL_WEBHOOK_ID}|${webhookEventBody}`;

    // Step 3: Verify signature
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(expectedSig);
    verifier.end();

    const isValid = verifier.verify(certPem, transmissionSig, 'base64');

    if (isValid) {
      console.log('✅ Signature verified!');
      res.sendStatus(200);
    } else {
      console.error('❌ Signature verification failed.');
      res.sendStatus(400);
    }
  } catch (error) {
    console.error('Error verifying signature:', error.message);
    res.sendStatus(500);
  }
});

app.listen(port, () => {
  console.log(`Node server listening at http://localhost:${port}/`);
});
