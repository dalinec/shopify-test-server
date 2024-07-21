const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

app.use(bodyParser.json());
app.use(cors());

const { SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, SHOPIFY_STORE_URL } =
  process.env;

let accessToken = '';

// Step 1: Redirect to Shopify to get the authorization code
app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop) {
    return res.status(400).send('Missing shop parameter.');
  }

  const redirectUri = `https://${req.get('host')}/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_CLIENT_ID}&scope=write_customers&redirect_uri=${redirectUri}`;

  res.redirect(installUrl);
});

// Step 2: Shopify redirects to this endpoint with the authorization code
app.get('/callback', async (req, res) => {
  const { shop, code } = req.query;

  if (!shop || !code) {
    return res.status(400).send('Required parameters missing.');
  }

  try {
    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code,
      }
    );

    accessToken = response.data.access_token;

    res.send('Authorization successful! You can now close this tab.');
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Step 3: Use the access token to create a customer
app.post('/api/create-customer', async (req, res) => {
  const { name, email } = req.body;

  if (!accessToken) {
    return res.status(401).send('Unauthorized: Missing access token.');
  }

  try {
    const response = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/2021-01/customers.json`,
      {
        customer: {
          first_name: name,
          email: email,
          verified_email: true,
          accepts_marketing: true,
        },
      },
      {
        headers: {
          'X-Shopify-Access-Token': accessToken,
          'Content-Type': 'application/json',
        },
      }
    );

    if (response.data.customer) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: 'Failed to create customer.' });
    }
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});