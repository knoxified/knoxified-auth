require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const providers = require('./providers');

const app = express();

// In-memory lock to prevent concurrent token refresh for the same user
const refreshLocks = new Map();

app.use(cors());
app.use(express.json());

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

/**
 * Supabase headers (single source of truth)
 */
function sbHeaders() {
  return {
    apikey: SUPABASE_KEY,
    Authorization: `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json'
  };
}

/**
 * HEALTH
 */
app.get('/', (req, res) => {
  res.json({ status: 'Knoxified Auth Service Running' });
});

/**
 * START OAUTH (HARDENED)
 */
app.get('/auth/:provider/start', async (req, res) => {
  try {
    const { provider } = req.params;

    const config = providers[provider];
    if (!config) return res.status(400).json({ error: 'Unsupported provider' });

    const clientId = process.env[`${provider.toUpperCase()}_CLIENT_ID`];

    const userId = req.query.user_id;
    if (!userId) {
      return res.status(400).json({ error: 'Missing user_id' });
    }

    const state = `${provider}-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    await axios.delete(
      `${SUPABASE_URL}/rest/v1/oauth_sessions?user_id=eq.${userId}&provider=eq.${provider}`,
      { headers: sbHeaders() }
    );

    await axios.post(
      `${SUPABASE_URL}/rest/v1/oauth_sessions`,
      {
        user_id: userId,
        provider,
        state,
        used: false,
        expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString()
      },
      { headers: sbHeaders() }
    );

    const scope = Array.isArray(config.scopes)
      ? config.scopes.join(' ')
      : '';

    const url =
      `${config.authUrl}?client_id=${clientId}` +
      `&redirect_uri=${encodeURIComponent(config.redirectUri)}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent(scope)}` +
      `&access_type=${config.accessType || 'offline'}` +
      `&prompt=${config.prompt || 'consent'}` +
      `&state=${state}`;

    return res.redirect(url);

  } catch (err) {
    console.log(err.response?.data || err.message);
    return res.status(500).json({ error: 'start_failed' });
  }
});

/**
 * REFRESH ENGINE
 */
async function refreshGoogleToken(refresh_token) {
  const res = await axios.post(
    'https://oauth2.googleapis.com/token',
    new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      refresh_token,
      grant_type: 'refresh_token'
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );

  return res.data;
}

/**
 * GET VALID GOOGLE TOKEN (RACE-CONDITION SAFE)
 */
async function getValidGoogleToken(userId) {
  // If a refresh is already in progress for this user, wait for it
  if (refreshLocks.has(userId)) {
    console.log(`[LOCK] Waiting for existing refresh for user ${userId}`);
    return refreshLocks.get(userId);
  }

  // Create a new refresh promise
  const refreshPromise = (async () => {
    try {
      const response = await axios.get(
        `${SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.google&order=created_at.desc&limit=1`,
        { headers: sbHeaders() }
      );

      const connection = response.data?.[0];
      if (!connection) throw new Error('No Google connection found');

      const expiresAt = new Date(connection.expires_at).getTime();
      if (expiresAt > Date.now() + 60000) {
        return connection.access_token;
      }

      // Refresh the token
      console.log(`[REFRESH] Refreshing token for user ${userId}`);
      const refreshed = await refreshGoogleToken(connection.refresh_token);

      if (!refreshed.access_token) throw new Error('Refresh failed – no access token returned');

      // Update Supabase with the new token
      await axios.patch(
        `${SUPABASE_URL}/rest/v1/oauth_connections?id=eq.${connection.id}`,
        {
          access_token: refreshed.access_token,
          expires_at: new Date(Date.now() + refreshed.expires_in * 1000).toISOString(),
          refresh_token: refreshed.refresh_token || connection.refresh_token
        },
        { headers: sbHeaders() }
      );

      console.log(`[REFRESH] Token refreshed successfully for user ${userId}`);
      return refreshed.access_token;

    } catch (err) {
      console.log(`[REFRESH FAILED] ${err.response?.data || err.message}`);
      throw err;
    } finally {
      refreshLocks.delete(userId);   // always remove the lock
    }
  })();

  refreshLocks.set(userId, refreshPromise);
  return refreshPromise;
}

/**
 * CALLBACK (UNCHANGED + DEBUG LOG ADDED)
 */
app.get('/auth/:provider/callback', async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, state } = req.query;

    const config = providers[provider];

    const clientId = process.env[`${provider.toUpperCase()}_CLIENT_ID`];
    const clientSecret = process.env[`${provider.toUpperCase()}_CLIENT_SECRET`];

    const sessionRes = await axios.get(
      `${SUPABASE_URL}/rest/v1/oauth_sessions?state=eq.${state}`,
      { headers: sbHeaders() }
    );

    const session = sessionRes.data?.[0];

    if (!session) {
      return res.redirect(`https://knoxified.org?status=invalid_state`);
    }

    if (session.used) {
      return res.redirect(`https://knoxified.org?status=already_used`);
    }

    const userId = session.user_id;

    console.log({
      code,
      clientId,
      clientSecret,
      redirectUri: config.redirectUri
    });

    const tokenResponse = await axios.post(
      config.tokenUrl,
      new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: config.redirectUri,
        grant_type: 'authorization_code'
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const tokens = tokenResponse.data;

    if (!tokens.access_token) {
      return res.redirect(`https://knoxified.org?status=token_missing`);
    }

    try {
      await axios.post(
        `${SUPABASE_URL}/rest/v1/oauth_connections`,
        {
          user_id: userId,
          provider,
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          expires_at: new Date(Date.now() + tokens.expires_in * 1000).toISOString(),
          status: 'active'
        },
        { headers: sbHeaders() }
      );
    } catch (dbErr) {
      console.log('SUPABASE SAVE ERROR:', dbErr.response?.data || dbErr.message);
      return res.redirect(`https://knoxified.org?status=db_save_failed`);
    }

    await axios.patch(
      `${SUPABASE_URL}/rest/v1/oauth_sessions?state=eq.${state}`,
      { used: true },
      { headers: sbHeaders() }
    );

    return res.redirect(
      `https://knoxified.org?provider=${provider}&status=connected`
    );

  } catch (err) {
    console.log('OAuth Error:', err.response?.data || err.message);

    return res.redirect(
      `https://knoxified.org?status=failed&reason=${encodeURIComponent(err.message)}`
    );
  }
});

/**
 * REFRESH ENDPOINT
 */
app.post('/auth/refresh/google', async (req, res) => {
  try {
    const { refresh_token } = req.body;
    const newTokens = await refreshGoogleToken(refresh_token);
    return res.json(newTokens);
  } catch (err) {
    return res.status(500).json({ error: 'refresh_failed' });
  }
});

/**
 * TOKEN RESOLVER ENDPOINT (WITH LOCK & PERMANENT-FAILURE HANDLING)
 */
app.post('/auth/:provider/token', async (req, res) => {
  try {
    console.log('TOKEN ENDPOINT HIT', req.body);  // remove in production
    const { provider } = req.params;
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'missing_userId' });
    }

    if (provider === 'google') {
      const accessToken = await getValidGoogleToken(userId);
      return res.json({ accessToken });
    }

    // fallback for other providers
    const response = await axios.get(
      `${SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.${provider}`,
      { headers: sbHeaders() }
    );
    const connection = response.data?.[0];
    if (!connection) {
      return res.status(404).json({ error: 'no_connection_found' });
    }
    return res.json({ accessToken: connection.access_token });

  } catch (err) {
    const status = err.response?.data?.error === 'invalid_grant' ? 401 : 500;
    console.log('TOKEN ERROR:', err.response?.data || err.message);
    return res.status(status).json({
      error: 'token_fetch_failed',
      reason: err.response?.data || err.message
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});