import { Hono } from 'hono';
import providers from './providers.js';

const app = new Hono();

// In-memory lock to prevent concurrent token refresh for the same user.
//
// IMPORTANT LIMITATION vs. the old always-on Node server: this only
// protects concurrent requests that happen to land on the SAME Worker
// isolate. Cloudflare can and does run multiple isolates for the same
// Worker across its edge network, so two concurrent requests from
// different locations won't see each other's lock here the way they
// would have on a single persistent process. Practical impact is low --
// Google's OAuth refresh tokens aren't single-use by default, so a rare
// double-refresh just means two valid access tokens get issued instead
// of one, not a broken auth state. A fully airtight lock across the
// whole edge network would need a Durable Object. Flagging this instead
// of silently pretending the guarantee is unchanged.
const refreshLocks = new Map();

function sbHeaders(env) {
  return {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json'
  };
}

// fetch() doesn't throw on 4xx/5xx like axios did -- this restores that
// behavior so existing try/catch blocks keep working the same way.
async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const err = new Error(`Request failed: ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

/**
 * HEALTH
 */
app.get('/', (c) => {
  return c.json({ status: 'Knoxified Auth Service Running' });
});

/**
 * START OAUTH
 */
app.get('/auth/:provider/start', async (c) => {
  const env = c.env;
  try {
    const provider = c.req.param('provider');
    const config = providers[provider];
    if (!config) return c.json({ error: 'Unsupported provider' }, 400);

    const clientId = env[`${provider.toUpperCase()}_CLIENT_ID`];

    const userId = c.req.query('user_id');
    if (!userId) {
      return c.json({ error: 'Missing user_id' }, 400);
    }

    // Where to send the user back to on the dashboard once this finishes.
    // Only allow a relative path (must start with /) so this can't be used
    // to redirect somewhere off-site.
    const returnToParam = c.req.query('return_to');
    const returnPath =
      typeof returnToParam === 'string' && returnToParam.startsWith('/')
        ? returnToParam
        : '/integrations';

    const state = `${provider}-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    await fetch(
      `${env.SUPABASE_URL}/rest/v1/oauth_sessions?user_id=eq.${userId}&provider=eq.${provider}`,
      { method: 'DELETE', headers: sbHeaders(env) }
    );

    await fetchJson(`${env.SUPABASE_URL}/rest/v1/oauth_sessions`, {
      method: 'POST',
      headers: sbHeaders(env),
      body: JSON.stringify({
        user_id: userId,
        provider,
        state,
        used: false,
        return_path: returnPath,
        expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString()
      })
    });

    const scope = Array.isArray(config.scopes) ? config.scopes.join(' ') : '';

    const url =
      `${config.authUrl}?client_id=${clientId}` +
      `&redirect_uri=${encodeURIComponent(config.redirectUri)}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent(scope)}` +
      `&access_type=${config.accessType || 'offline'}` +
      `&prompt=${config.prompt || 'consent'}` +
      `&state=${state}`;

    return c.redirect(url);

  } catch (err) {
    console.log(err.data || err.message);
    return c.json({ error: 'start_failed' }, 500);
  }
});

/**
 * REFRESH ENGINE
 */
async function refreshGoogleToken(env, refresh_token) {
  return fetchJson('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token,
      grant_type: 'refresh_token'
    })
  });
}

/**
 * GET VALID GOOGLE TOKEN
 *
 * Two layers here:
 * - refreshLocks (in-memory Map): a fast-path optimization only, avoids a
 *   redundant DB round-trip when multiple requests land on the same
 *   isolate. NOT relied on for correctness.
 * - refresh_claimed_until (DB column, atomic conditional UPDATE): the real
 *   cross-instance lock. Only one concurrent caller's PATCH can match the
 *   WHERE clause, no matter how many separate servers/isolates/instances
 *   are handling requests -- the database is the single source of truth.
 *   This is what actually makes concurrent refreshes safe, regardless of
 *   hosting platform.
 */
async function getValidGoogleToken(env, userId) {
  if (refreshLocks.has(userId)) {
    console.log(`[LOCK] Waiting for existing refresh for user ${userId}`);
    return refreshLocks.get(userId);
  }

  const refreshPromise = (async () => {
    try {
      const rows = await fetchJson(
        `${env.SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.google&order=created_at.desc&limit=1`,
        { headers: sbHeaders(env) }
      );

      const connection = rows?.[0];
      if (!connection) throw new Error('No Google connection found');

      const expiresAt = new Date(connection.expires_at).getTime();
      if (expiresAt > Date.now() + 60000) {
        return connection.access_token;
      }

      // Try to atomically claim the right to refresh this connection.
      const claimUntil = new Date(Date.now() + 15000).toISOString();
      const nowIso = new Date().toISOString();

      const claimed = await fetchJson(
        `${env.SUPABASE_URL}/rest/v1/oauth_connections?id=eq.${connection.id}` +
          `&or=(refresh_claimed_until.is.null,refresh_claimed_until.lt.${encodeURIComponent(nowIso)})`,
        {
          method: 'PATCH',
          headers: { ...sbHeaders(env), Prefer: 'return=representation' },
          body: JSON.stringify({ refresh_claimed_until: claimUntil })
        }
      );

      if (!claimed || claimed.length === 0) {
        // Someone else already claimed this refresh (a different instance
        // entirely, possibly). Their refresh should complete in well
        // under a second in practice -- wait briefly and read whatever
        // they wrote instead of racing them or refreshing twice.
        console.log(`[CLAIM] Refresh already claimed for user ${userId}, waiting`);
        await new Promise((resolve) => setTimeout(resolve, 1500));

        const latestRows = await fetchJson(
          `${env.SUPABASE_URL}/rest/v1/oauth_connections?id=eq.${connection.id}`,
          { headers: sbHeaders(env) }
        );
        const latest = latestRows?.[0];
        if (latest && new Date(latest.expires_at).getTime() > Date.now()) {
          return latest.access_token;
        }
        // Still not refreshed (e.g. the other claimant failed partway
        // through) -- fall through and refresh ourselves rather than
        // give up.
      }

      console.log(`[REFRESH] Refreshing token for user ${userId}`);
      const refreshed = await refreshGoogleToken(env, connection.refresh_token);

      if (!refreshed.access_token) throw new Error('Refresh failed – no access token returned');

      await fetchJson(`${env.SUPABASE_URL}/rest/v1/oauth_connections?id=eq.${connection.id}`, {
        method: 'PATCH',
        headers: sbHeaders(env),
        body: JSON.stringify({
          access_token: refreshed.access_token,
          expires_at: new Date(Date.now() + refreshed.expires_in * 1000).toISOString(),
          refresh_token: refreshed.refresh_token || connection.refresh_token,
          refresh_claimed_until: null
        })
      });

      console.log(`[REFRESH] Token refreshed successfully for user ${userId}`);
      return refreshed.access_token;

    } catch (err) {
      console.log(`[REFRESH FAILED] ${JSON.stringify(err.data) || err.message}`);
      throw err;
    } finally {
      refreshLocks.delete(userId);
    }
  })();

  refreshLocks.set(userId, refreshPromise);
  return refreshPromise;
}

/**
 * CALLBACK
 */
app.get('/auth/:provider/callback', async (c) => {
  const env = c.env;
  const DASHBOARD_BASE_URL = 'https://dashboard.knoxified.org';
  // Default used only if we fail before we can look up the session (so we
  // still have somewhere safe to send the user back to).
  let returnPath = '/integrations';

  try {
    const provider = c.req.param('provider');
    const code = c.req.query('code');
    const state = c.req.query('state');

    const config = providers[provider];
    const clientId = env[`${provider.toUpperCase()}_CLIENT_ID`];
    const clientSecret = env[`${provider.toUpperCase()}_CLIENT_SECRET`];

    const sessions = await fetchJson(
      `${env.SUPABASE_URL}/rest/v1/oauth_sessions?state=eq.${state}`,
      { headers: sbHeaders(env) }
    );

    const session = sessions?.[0];

    if (!session) {
      return c.redirect(`${DASHBOARD_BASE_URL}${returnPath}?status=invalid_state`);
    }

    returnPath = session.return_path || returnPath;

    if (session.used) {
      return c.redirect(`${DASHBOARD_BASE_URL}${returnPath}?status=already_used`);
    }

    const userId = session.user_id;

    const tokens = await fetchJson(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: config.redirectUri,
        grant_type: 'authorization_code'
      })
    });

    if (!tokens.access_token) {
      return c.redirect(`${DASHBOARD_BASE_URL}${returnPath}?status=token_missing`);
    }

    try {
      await fetchJson(`${env.SUPABASE_URL}/rest/v1/oauth_connections`, {
        method: 'POST',
        headers: sbHeaders(env),
        body: JSON.stringify({
          user_id: userId,
          provider,
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          expires_at: new Date(Date.now() + tokens.expires_in * 1000).toISOString(),
          status: 'active'
        })
      });
    } catch (dbErr) {
      console.log('SUPABASE SAVE ERROR:', dbErr.data || dbErr.message);
      return c.redirect(`${DASHBOARD_BASE_URL}${returnPath}?status=db_save_failed`);
    }

    await fetch(`${env.SUPABASE_URL}/rest/v1/oauth_sessions?state=eq.${state}`, {
      method: 'PATCH',
      headers: sbHeaders(env),
      body: JSON.stringify({ used: true })
    });

    return c.redirect(
      `${DASHBOARD_BASE_URL}${returnPath}?provider=${provider}&status=connected`
    );

  } catch (err) {
    console.log('OAuth Error:', err.data || err.message);
    return c.redirect(
      `${DASHBOARD_BASE_URL}${returnPath}?status=failed&reason=${encodeURIComponent(err.message)}`
    );
  }
});

/**
 * REFRESH ENDPOINT
 */
app.post('/auth/refresh/google', async (c) => {
  try {
    const { refresh_token } = await c.req.json();
    const newTokens = await refreshGoogleToken(c.env, refresh_token);
    return c.json(newTokens);
  } catch (err) {
    return c.json({ error: 'refresh_failed' }, 500);
  }
});

/**
 * TOKEN RESOLVER ENDPOINT (WITH LOCK & PERMANENT-FAILURE HANDLING)
 */
app.post('/auth/:provider/token', async (c) => {
  const env = c.env;
  try {
    const provider = c.req.param('provider');
    const { userId } = await c.req.json();

    if (!userId) {
      return c.json({ error: 'missing_userId' }, 400);
    }

    if (provider === 'google') {
      const accessToken = await getValidGoogleToken(env, userId);
      return c.json({ accessToken });
    }

    const rows = await fetchJson(
      `${env.SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.${provider}`,
      { headers: sbHeaders(env) }
    );
    const connection = rows?.[0];
    if (!connection) {
      return c.json({ error: 'no_connection_found' }, 404);
    }
    return c.json({ accessToken: connection.access_token });

  } catch (err) {
    const status = err.data?.error === 'invalid_grant' ? 401 : 500;
    console.log('TOKEN ERROR:', err.data || err.message);
    return c.json({
      error: 'token_fetch_failed',
      reason: err.data || err.message
    }, status);
  }
});

export default app;
