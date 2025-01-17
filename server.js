const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 5000;

app.use(bodyParser.json());
app.use(cors());

const {
  SHOPIFY_CLIENT_ID,
  SHOPIFY_CLIENT_SECRET,
  SHOPIFY_STORE_URL,
  ACCESS_TOKEN,
} = process.env;

if (!SHOPIFY_CLIENT_SECRET) {
  console.error('SHOPIFY_CLIENT_SECRET is not set.');
  process.exit(1);
}

let accessToken = '';

//Redirect to Shopify to get the authorization code
app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop) {
    return res.status(400).send('Missing shop parameter.');
  }

  const redirectUri = `https://shopify-test-server.onrender.com/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_CLIENT_ID}&scope=write_customers&redirect_uri=${encodeURIComponent(
    redirectUri
  )}`;

  res.redirect(installUrl);
});

//Shopify redirects to this endpoint with the authorization code
app.get('/callback', async (req, res) => {
  const { shop, code, hmac } = req.query;

  if (!shop || !code || !hmac) {
    console.error('Missing parameters:', req.query);
    return res.status(400).send('Required parameters missing.');
  }

  try {
    const generatedHmac = crypto
      .createHmac('sha256', SHOPIFY_CLIENT_SECRET)
      .update(
        new URLSearchParams(
          Object.fromEntries(
            Object.entries(req.query).filter(([key]) => key !== 'hmac')
          )
        ).toString()
      )
      .digest('hex');

    if (generatedHmac !== hmac) {
      console.error('HMAC validation failed:', {
        generatedHmac,
        receivedHmac: hmac,
      });
      return res.status(400).send('HMAC validation failed.');
    }

    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code,
      }
    );

    accessToken = response.data.access_token;

    res.send(
      `Authorization successful! You can now close this tab. The access token is ${accessToken}`
    );
  } catch (error) {
    console.error(
      'Error during callback:',
      error.response ? error.response.data : error.message
    );
    res.status(500).send('Error during callback');
  }
});

// Use the access token to create a customer
app.post('/api/create-customer', async (req, res) => {
  const { name, email } = req.body;

  const nameParts = name.split(' ');
  const first_name = nameParts[0];
  const last_name = nameParts.slice(1).join(' ');

  // if (!accessToken) {
  //   return res
  //     .status(401)
  //     .json({ message: 'Unauthorized: Missing access token.' });
  // }

  try {
    const response = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/2024-07/customers.json`,
      {
        customer: {
          first_name: first_name,
          last_name: last_name,
          email: email,
          verified_email: true,
          accepts_marketing: true,
          email_marketing_consent: {
            state: 'subscribed',
            opt_in_level: 'confirmed_opt_in',
            consent_updated_at: new Date(),
          },
        },
      },
      {
        headers: {
          'X-Shopify-Access-Token': ACCESS_TOKEN,
          'Content-Type': 'application/json',
        },
      }
    );

    console.log('Shopify response:', response.data); // Log response

    if (response.data.customer) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: 'Failed to create customer.' });
    }
  } catch (error) {
    console.error(
      'Error creating customer:',
      error.response ? error.response.data : error.message
    );
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/check-token', (req, res) => {
  res.json({ accessToken });
});

console.log(accessToken);
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
