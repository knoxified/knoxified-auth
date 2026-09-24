const BASE_URL = "https://oauth.knoxified.org";

const providers = {
  google: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scopes: [
      "openid",
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email",
      "https://www.googleapis.com/auth/calendar.events",          // create / edit events
      "https://www.googleapis.com/auth/calendar.freebusy",        // check free/busy
      "https://www.googleapis.com/auth/calendar.calendars.readonly", // read calendar list
      "https://www.googleapis.com/auth/spreadsheets",             // Sheets (CRM)
      "https://www.googleapis.com/auth/gmail.send",               // send email
      "https://www.googleapis.com/auth/gmail.readonly",           // read email (if needed)
      "https://www.googleapis.com/auth/drive.file"                // optional, for Drive files
    ],
    accessType: "offline",
    prompt: "consent",
    redirectUri: `${BASE_URL}/auth/google/callback`
  },

  microsoft: {
    authUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    // Mail.Send lets Knoxified send email sequences from the customer's own
    // Outlook / Microsoft 365 mailbox. Existing connections made before this
    // scope was added must reconnect once to grant it.
    scopes: ["User.Read", "offline_access", "Mail.Send"],
    redirectUri: `${BASE_URL}/auth/microsoft/callback`
  },

  // Zoho Mail. Zoho runs separate data centers (.com, .eu, .in, .com.au ...)
  // and tells us which one the customer's account lives in via the
  // "accounts-server" query param on the callback; index.js stores that with
  // the connection and uses it for every later token/refresh call.
  zoho: {
    authUrl: "https://accounts.zoho.com/oauth/v2/auth",
    tokenUrl: "https://accounts.zoho.com/oauth/v2/token",
    scopes: ["ZohoMail.messages.CREATE", "ZohoMail.accounts.READ"],
    scopeSeparator: ",",
    accessType: "offline",
    prompt: "consent",
    redirectUri: `${BASE_URL}/auth/zoho/callback`
  },

  notion: {
    authUrl: "https://api.notion.com/v1/oauth/authorize",
    tokenUrl: "https://api.notion.com/v1/oauth/token",
    scopes: [],
    redirectUri: `${BASE_URL}/auth/notion/callback`
  },

  slack: {
    authUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    scopes: ["channels:read", "chat:write", "users:read"],
    redirectUri: `${BASE_URL}/auth/slack/callback`
  },

  github: {
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    scopes: ["repo", "user"],
    redirectUri: `${BASE_URL}/auth/github/callback`
  },

  linkedin: {
    authUrl: "https://www.linkedin.com/oauth/v2/authorization",
    tokenUrl: "https://www.linkedin.com/oauth/v2/accessToken",
    scopes: ["r_liteprofile", "r_emailaddress"],
    redirectUri: `${BASE_URL}/auth/linkedin/callback`
  },

  meta: {
    authUrl: "https://www.facebook.com/v19.0/dialog/oauth",
    tokenUrl: "https://graph.facebook.com/v19.0/oauth/access_token",
    scopes: ["email", "public_profile"],
    redirectUri: `${BASE_URL}/auth/meta/callback`
  }
};

export default providers;
