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

// Providers whose access tokens expire and are renewed through getValidToken.
const REFRESHABLE = new Set(['google', 'microsoft', 'zoho']);

// Zoho tells the callback which data center the customer's account is in.
// Only ever trust a real Zoho accounts host: this value is used to build the
// URL we send client credentials to.
const ZOHO_ACCOUNTS_RE = /^accounts\.(zoho\.(com|eu|in|com\.au|jp|sa|com\.cn)|zohocloud\.ca)$/;
function zohoAccountsServer(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && ZOHO_ACCOUNTS_RE.test(u.hostname) ? `https://${u.hostname}` : null;
  } catch {
    return null;
  }
}

// Zoho has returned expiry both in seconds and in milliseconds over time.
function ttlSeconds(tokens) {
  if (Number(tokens.expires_in_sec) > 0) return Number(tokens.expires_in_sec);
  const n = Number(tokens.expires_in) || 3600;
  return n > 100000 ? Math.round(n / 1000) : n;
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Service-to-service protection for the routes that hand out or spend tokens.
// OPT-IN so nothing breaks the moment this deploys: enforced only once an
// INTERNAL_API_KEY secret exists on this Worker, at which point every caller
// (n8n, voice agent, ...) must send it as the x-internal-key header.
function internalKeyOk(c) {
  const key = c.env.INTERNAL_API_KEY;
  if (!key) return true;
  return constantTimeEqual(c.req.header('x-internal-key') || '', key);
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

    const scope = Array.isArray(config.scopes) ? config.scopes.join(config.scopeSeparator || ' ') : '';

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

// Same refresh grant for every provider that supports it. Credentials come
// from <PROVIDER>_CLIENT_ID / <PROVIDER>_CLIENT_SECRET, exactly like the
// authorization-code exchange in the callback.
async function refreshAccessToken(env, provider, connection) {
  let tokenUrl = providers[provider].tokenUrl;
  if (provider === 'zoho') {
    const server = zohoAccountsServer(connection.metadata?.accounts_server);
    if (server) tokenUrl = `${server}/oauth/v2/token`;
  }
  return fetchJson(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env[`${provider.toUpperCase()}_CLIENT_ID`],
      client_secret: env[`${provider.toUpperCase()}_CLIENT_SECRET`],
      refresh_token: connection.refresh_token,
      grant_type: 'refresh_token'
    })
  });
}

/**
 * GET VALID TOKEN (google, microsoft, zoho)
 *
 * Two layers here:
 * - refreshLocks (in-memory Map): a fast-path optimization only, avoids a
 *   redundant DB round-trip when multiple requests land on the same
 *   isolate. NOT relied on for correctness. Keyed by provider AND user: with
 *   several providers per user, a user-only key would make a Google refresh
 *   answer a Microsoft request.
 * - refresh_claimed_until (DB column, atomic conditional UPDATE): the real
 *   cross-instance lock. Only one concurrent caller's PATCH can match the
 *   WHERE clause, no matter how many separate servers/isolates/instances
 *   are handling requests -- the database is the single source of truth.
 *   This matters most for Microsoft, which rotates the refresh token on every
 *   refresh: two racing refreshes could otherwise invalidate each other.
 */
async function getValidToken(env, userId, provider) {
  const lockKey = `${provider}:${userId}`;
  if (refreshLocks.has(lockKey)) {
    console.log(`[LOCK] Waiting for existing ${provider} refresh for user ${userId}`);
    return refreshLocks.get(lockKey);
  }

  const refreshPromise = (async () => {
    try {
      const rows = await fetchJson(
        `${env.SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.${provider}&order=created_at.desc&limit=1`,
        { headers: sbHeaders(env) }
      );

      const connection = rows?.[0];
      if (!connection) {
        const notFound = new Error(`No ${provider} connection found`);
        notFound.notFound = true;
        throw notFound;
      }
      const metadata = connection.metadata || null;

      const expiresAt = new Date(connection.expires_at).getTime();
      if (expiresAt > Date.now() + 60000) {
        return { accessToken: connection.access_token, metadata };
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
        console.log(`[CLAIM] ${provider} refresh already claimed for user ${userId}, waiting`);
        await new Promise((resolve) => setTimeout(resolve, 1500));

        const latestRows = await fetchJson(
          `${env.SUPABASE_URL}/rest/v1/oauth_connections?id=eq.${connection.id}`,
          { headers: sbHeaders(env) }
        );
        const latest = latestRows?.[0];
        if (latest && new Date(latest.expires_at).getTime() > Date.now()) {
          return { accessToken: latest.access_token, metadata: latest.metadata || null };
        }
        // Still not refreshed (e.g. the other claimant failed partway
        // through) -- fall through and refresh ourselves rather than
        // give up.
      }

      console.log(`[REFRESH] Refreshing ${provider} token for user ${userId}`);
      const refreshed = await refreshAccessToken(env, provider, connection);

      if (!refreshed.access_token) throw new Error('Refresh failed – no access token returned');

      await fetchJson(`${env.SUPABASE_URL}/rest/v1/oauth_connections?id=eq.${connection.id}`, {
        method: 'PATCH',
        headers: sbHeaders(env),
        body: JSON.stringify({
          access_token: refreshed.access_token,
          expires_at: new Date(Date.now() + ttlSeconds(refreshed) * 1000).toISOString(),
          refresh_token: refreshed.refresh_token || connection.refresh_token,
          refresh_claimed_until: null
        })
      });

      console.log(`[REFRESH] ${provider} token refreshed successfully for user ${userId}`);
      return { accessToken: refreshed.access_token, metadata };

    } catch (err) {
      console.log(`[REFRESH FAILED] ${JSON.stringify(err.data) || err.message}`);
      throw err;
    } finally {
      refreshLocks.delete(lockKey);
    }
  })();

  refreshLocks.set(lockKey, refreshPromise);
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

    // Zoho: exchange the code against the data center the account lives in.
    let tokenUrl = config.tokenUrl;
    let connectionMetadata;
    if (provider === 'zoho') {
      const server = zohoAccountsServer(c.req.query('accounts-server'));
      if (server) {
        tokenUrl = `${server}/oauth/v2/token`;
        connectionMetadata = { accounts_server: server };
      }
    }

    const tokens = await fetchJson(tokenUrl, {
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
          expires_at: new Date(Date.now() + ttlSeconds(tokens) * 1000).toISOString(),
          status: 'active',
          // Only sent when there is something to store, so providers that
          // don't need it work even before the metadata column exists.
          ...(connectionMetadata ? { metadata: connectionMetadata } : {})
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
  if (!internalKeyOk(c)) return c.json({ error: 'unauthorized' }, 401);
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
  if (!internalKeyOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const env = c.env;
  try {
    const provider = c.req.param('provider');
    const { userId } = await c.req.json();

    if (!userId) {
      return c.json({ error: 'missing_userId' }, 400);
    }

    if (REFRESHABLE.has(provider)) {
      const { accessToken, metadata } = await getValidToken(env, userId, provider);
      return c.json({ accessToken, metadata });
    }

    // Newest connection wins (callbacks insert a new row on every connect).
    const rows = await fetchJson(
      `${env.SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.${provider}&order=created_at.desc&limit=1`,
      { headers: sbHeaders(env) }
    );
    const connection = rows?.[0];
    if (!connection) {
      return c.json({ error: 'no_connection_found' }, 404);
    }
    return c.json({ accessToken: connection.access_token, metadata: connection.metadata || null });

  } catch (err) {
    if (err.notFound) return c.json({ error: 'no_connection_found' }, 404);
    const status = err.data?.error === 'invalid_grant' ? 401 : 500;
    console.log('TOKEN ERROR:', err.data || err.message);
    return c.json({
      error: 'token_fetch_failed',
      reason: err.data || err.message
    }, status);
  }
});

/**
 * API-KEY CONNECTIONS (Cal.com)
 *
 * Not OAuth: the customer pastes an API key from Cal.com (Settings > Developer >
 * API keys). It is validated against Cal.com, then stored as a normal
 * oauth_connections row (provider 'calcom', access_token = the key, no refresh
 * token, no expiry) so /auth/calcom/token works exactly like every other provider.
 *
 * These routes are called by the dashboard SERVER (never the browser) and fail
 * CLOSED: without a CONNECT_API_KEY secret on this Worker they refuse every
 * request, because they write credentials for a user_id they are given.
 */
const CALCOM_API = 'https://api.cal.com/v2';
const CALCOM_VERSION = '2024-08-13';

function connectKeyOk(c) {
  const key = c.env.CONNECT_API_KEY;
  if (!key) return false;
  return constantTimeEqual(c.req.header('x-connect-key') || '', key);
}

async function calcomGet(path, apiKey, version = CALCOM_VERSION) {
  const res = await fetch(`${CALCOM_API}${path}`, {
    headers: { Authorization: `Bearer ${apiKey}`, 'cal-api-version': version }
  });
  const text = await res.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { ok: res.ok, status: res.status, body };
}

// Validates the key and lists the account's event types. Throws a tagged error
// the routes turn into a clean response.
async function inspectCalcomKey(apiKey) {
  if (typeof apiKey !== 'string' || apiKey.trim().length < 10 || apiKey.length > 300) {
    const e = new Error('invalid_api_key'); e.code = 'invalid_api_key'; throw e;
  }
  const key = apiKey.trim();

  const me = await calcomGet('/me', key);
  if (me.status === 401 || me.status === 403) {
    const e = new Error('invalid_api_key'); e.code = 'invalid_api_key'; throw e;
  }
  if (!me.ok || !me.body?.data) {
    const e = new Error('calcom_unavailable'); e.code = 'calcom_unavailable'; throw e;
  }
  const user = me.body.data;

  // Event-type endpoints have used different version headers over time: try the
  // documented one first, then the older one.
  let list = await calcomGet('/event-types', key);
  if (!list.ok) list = await calcomGet('/event-types', key, '2024-06-14');
  if (!list.ok) {
    const e = new Error('calcom_unavailable'); e.code = 'calcom_unavailable'; throw e;
  }
  const data = list.body?.data;
  const raw = Array.isArray(data)
    ? data
    : (data?.eventTypeGroups || []).flatMap((g) => g.eventTypes || []);

  const eventTypes = raw
    .filter((t) => t && t.id)
    .map((t) => ({
      id: t.id,
      slug: t.slug,
      title: t.title,
      lengthMinutes: t.lengthInMinutes ?? t.length ?? null,
      hidden: !!t.hidden
    }));

  return { key, user, eventTypes };
}

function calcomErrorResponse(c, err) {
  if (err.code === 'invalid_api_key') return c.json({ error: 'invalid_api_key' }, 400);
  if (err.code === 'calcom_unavailable') return c.json({ error: 'calcom_unavailable' }, 502);
  console.log('CALCOM ERROR:', err.data || err.message);
  return c.json({ error: 'calcom_failed' }, 500);
}

// Step 1: check the key and return the event types to choose from (saves nothing).
app.post('/auth/calcom/event-types', async (c) => {
  if (!connectKeyOk(c)) return c.json({ error: 'unauthorized' }, 401);
  try {
    const { apiKey } = await c.req.json();
    const { user, eventTypes } = await inspectCalcomKey(apiKey);
    return c.json({
      account: { username: user.username || null, email: user.email || null, timeZone: user.timeZone || null },
      eventTypes
    });
  } catch (err) {
    return calcomErrorResponse(c, err);
  }
});

// Step 2: save the connection with the chosen event type.
app.post('/auth/calcom/connect', async (c) => {
  if (!connectKeyOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const env = c.env;
  try {
    const { userId, apiKey, eventTypeId, setAsCalendar } = await c.req.json();
    if (!userId) return c.json({ error: 'missing_userId' }, 400);

    const { key, user, eventTypes } = await inspectCalcomKey(apiKey);
    const chosen = eventTypes.find((t) => String(t.id) === String(eventTypeId));
    if (!chosen) return c.json({ error: 'invalid_event_type', eventTypes }, 400);

    const inserted = await fetchJson(`${env.SUPABASE_URL}/rest/v1/oauth_connections`, {
      method: 'POST',
      headers: { ...sbHeaders(env), Prefer: 'return=representation' },
      body: JSON.stringify({
        user_id: userId,
        provider: 'calcom',
        provider_user_id: user.id != null ? String(user.id) : null,
        provider_email: user.email || null,
        access_token: key,
        refresh_token: null,
        expires_at: null,
        status: 'active',
        metadata: {
          eventTypeId: chosen.id,
          eventTypeSlug: chosen.slug || null,
          eventTypeTitle: chosen.title || null,
          lengthMinutes: chosen.lengthMinutes,
          timeZone: user.timeZone || null,
          username: user.username || null,
          apiVersion: CALCOM_VERSION
        }
      })
    });

    // Keep one Cal.com connection per user: drop older rows only after the new one is saved.
    const newId = inserted?.[0]?.id;
    if (newId) {
      await fetch(
        `${env.SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.calcom&id=neq.${newId}`,
        { method: 'DELETE', headers: sbHeaders(env) }
      );
    }

    // Optionally make Cal.com the calendar the voice agent uses.
    if (setAsCalendar === true) {
      await fetch(`${env.SUPABASE_URL}/rest/v1/agent_configs?user_id=eq.${userId}`, {
        method: 'PATCH',
        headers: sbHeaders(env),
        body: JSON.stringify({ calendar_provider: 'calcom' })
      });
    }

    return c.json({ ok: true, eventType: chosen, account: { username: user.username || null, email: user.email || null } });
  } catch (err) {
    return calcomErrorResponse(c, err);
  }
});

// Disconnect Cal.com: remove the stored key and fall back to Google if it was the active calendar.
app.post('/auth/calcom/disconnect', async (c) => {
  if (!connectKeyOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const env = c.env;
  try {
    const { userId } = await c.req.json();
    if (!userId) return c.json({ error: 'missing_userId' }, 400);
    await fetch(`${env.SUPABASE_URL}/rest/v1/oauth_connections?user_id=eq.${userId}&provider=eq.calcom`, {
      method: 'DELETE', headers: sbHeaders(env)
    });
    await fetch(`${env.SUPABASE_URL}/rest/v1/agent_configs?user_id=eq.${userId}&calendar_provider=eq.calcom`, {
      method: 'PATCH', headers: sbHeaders(env), body: JSON.stringify({ calendar_provider: 'google' })
    });
    return c.json({ ok: true });
  } catch (err) {
    console.log('CALCOM DISCONNECT ERROR:', err.data || err.message);
    return c.json({ error: 'calcom_failed' }, 500);
  }
});

export default app;
