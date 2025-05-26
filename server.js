import express from 'express';
import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
const port = process.env.PORT || 8888;

const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID; // safer from env

app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.post('/webhook', async (req, res) => {
  const headers = req.headers;

  console.log('headers', headers);
  console.log('parsed json', req.body);

  try {
    const verificationPayload = {
      auth_algo: headers['paypal-auth-algo'],
      cert_url: headers['paypal-cert-url'],
      transmission_id: headers['paypal-transmission-id'],
      transmission_sig: headers['paypal-transmission-sig'],
      transmission_time: headers['paypal-transmission-time'],
      webhook_id: PAYPAL_WEBHOOK_ID, // Your webhook ID from PayPal developer dashboard
      webhook_event: req.body
    };

    const accessToken = await getAccessToken();

    const response = await axios.post(
      'https://api.paypal.com/v1/notifications/verify-webhook-signature',
      verificationPayload,
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    if (response.data.verification_status === 'SUCCESS') {
      console.log('✅ Verified PayPal webhook');
      res.sendStatus(200);
    } else {
      console.error('❌ Invalid webhook signature');
      res.status(400).send('Invalid signature');
    }
  } catch (err) {
    console.error('Error during verification', err.message);
    res.status(500).send('Server error');
  }
});

// Step to get OAuth2 token from PayPal
async function getAccessToken() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const secret = process.env.PAYPAL_CLIENT_SECRET;

  const auth = Buffer.from(`${clientId}:${secret}`).toString('base64');

  const { data } = await axios.post(
    'https://api.paypal.com/v1/oauth2/token',
    'grant_type=client_credentials',
    {
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );

  return data.access_token;
}

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
