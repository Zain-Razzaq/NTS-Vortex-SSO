require('dotenv').config();

const dns = require('dns');
// On Alpine (musl libc), Node's dns.lookup() queries A and AAAA together,
// and musl fails the whole lookup with EAI_AGAIN if either sub-query gets a
// SERVFAIL from Docker's embedded DNS — even if the other one would have
// succeeded. This network doesn't need IPv6, so force IPv4-only lookups
// everywhere (setDefaultResultOrder alone isn't enough: it only reorders
// results after both queries already succeeded, it doesn't skip the AAAA one).
const originalDnsLookup = dns.lookup;
dns.lookup = (hostname, options, callback) => {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  } else if (typeof options === 'number') {
    options = { family: options };
  }
  return originalDnsLookup(hostname, { ...options, family: 4 }, callback);
};

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');

// ── Config (fail loudly if something critical is missing) ────────────
const {
  APP_PUBLIC_URL,
  OPEN_WEBUI_INTERNAL_URL,
  OPEN_WEBUI_DB_PATH,
  CRM_LOGIN_URL,
  NTS_JWT_SECRET,
  OPEN_WEBUI_ADMIN_API_KEY,
  SESSION_SECRET,
  TRUSTED_EMAIL_HEADER = 'X-User-Email',
  TRUSTED_NAME_HEADER = 'X-User-Name',
  PORT = 3000,
  APP_NAME = 'Vortex',
} = process.env;

const REQUIRED = {
  APP_PUBLIC_URL,
  OPEN_WEBUI_INTERNAL_URL,
  OPEN_WEBUI_DB_PATH,
  CRM_LOGIN_URL,
  NTS_JWT_SECRET,
  SESSION_SECRET,
};
for (const [key, val] of Object.entries(REQUIRED)) {
  if (!val || val.startsWith('replace-with')) {
    // eslint-disable-next-line no-console
    console.warn(`[startup warning] ${key} is not set (or still a placeholder). Related features will fail until it is configured.`);
  }
}

// Open WebUI's own /api/v1/auths/signin endpoint stops doing password
// verification entirely once WEBUI_AUTH_TRUSTED_EMAIL_HEADER is set (it
// requires the trusted header to be present on the request instead, and
// has no password fallback) — so local email/password login here reads
// Open WebUI's `auth` table directly and verifies the bcrypt hash itself.
// This needs read access to Open WebUI's webui.db (mount its data volume
// read-only into this container — see README).
let webuiDb = null;
if (OPEN_WEBUI_DB_PATH) {
  try {
    webuiDb = new Database(OPEN_WEBUI_DB_PATH, { readonly: true, fileMustExist: true });
  } catch (err) {
    console.warn(`[startup warning] could not open OPEN_WEBUI_DB_PATH (${OPEN_WEBUI_DB_PATH}): ${err.message}. Local email/password login will fail until this is fixed.`);
  }
}

// Verified against on a lookup miss / inactive account, so a bad email and a
// bad password take the same time as a correct email with a wrong password
// (mirrors Open WebUI's own authenticate_user timing-safety behavior).
const PLACEHOLDER_HASH = bcrypt.hashSync('placeholder-do-not-use', 10);

const CALLBACK_PATH = '/auth/sso';
const RETURN_URL = `${APP_PUBLIC_URL}${CALLBACK_PATH}`;

const NTS_JWT_ISSUER = 'crm.ntsconnect.com';
const NTS_JWT_AUDIENCE = 'authenticated';

// Replay protection: track jtis we've already consumed so a leaked/replayed
// SSO URL can't be used to start a second session. Entries are pruned once
// the token's own exp has passed (tokens are short-lived, so this stays small).
const usedTokenIds = new Map(); // jti -> exp (seconds since epoch)
function pruneUsedTokenIds() {
  const now = Date.now() / 1000;
  for (const [jti, exp] of usedTokenIds) {
    if (exp <= now) usedTokenIds.delete(jti);
  }
}

const app = express();
app.set('trust proxy', 1); // behind Coolify's Traefik proxy

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/static', express.static(path.join(__dirname, 'static')));

app.use(
  session({
    name: 'vortex_sso_sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true, // requires HTTPS (Coolify/Traefik terminates TLS in front)
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 12, // 12 hours
    },
  })
);

// ── Helpers ────────────────────────────────────────────────────────

const loginTemplate = fs.readFileSync(path.join(__dirname, 'views', 'login.html'), 'utf8');

function renderLogin({ error } = {}) {
  const errorBlock = error ? `<div class="error">${escapeHtml(error)}</div>` : '';
  return loginTemplate
    .replaceAll('{{APP_NAME}}', APP_NAME)
    .replaceAll('{{YEAR}}', String(new Date().getFullYear()))
    .replaceAll('{{LOGO_URL}}', `${APP_PUBLIC_URL}/static/logo.png`)
    .replaceAll('{{ERROR_BLOCK}}', errorBlock);
}

function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function requireSession(req, res, next) {
  if (req.session && req.session.email) return next();
  return res.redirect('/login');
}

// Strip characters that would make Node's setHeader() throw or that could be
// used to smuggle extra header lines, before a JWT/upstream-supplied value
// (email, name) becomes a trusted header value.
function sanitizeHeaderValue(value) {
  return String(value).replace(/[\r\n\t\x00-\x1f\x7f]/g, '').trim();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' },
});

// ── Routes: login (local + NTS CRM) ───────────────────────────────────

app.get('/login', (req, res) => {
  if (req.session && req.session.email) return res.redirect('/');
  res.type('html').send(renderLogin());
});

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).type('html').send(renderLogin({ error: 'Email and password are required.' }));
  }

  if (!webuiDb) {
    console.error('[nts-sso] local login attempted but OPEN_WEBUI_DB_PATH is not configured/reachable');
    return res.status(500).type('html').send(renderLogin({ error: 'Something went wrong. Please try again.' }));
  }

  try {
    const row = webuiDb
      .prepare(
        `SELECT auth.password AS password, auth.active AS active, user.email AS email, user.name AS name
         FROM auth JOIN user ON user.id = auth.id
         WHERE lower(auth.email) = lower(?)`
      )
      .get(email);

    const hashToCheck = row && row.active ? row.password : PLACEHOLDER_HASH;
    const ok = await bcrypt.compare(password, hashToCheck);

    if (!row || !row.active || !ok) {
      return res.status(401).type('html').send(renderLogin({ error: 'Invalid email or password.' }));
    }

    req.session.email = row.email;
    req.session.name = row.name || row.email;
    req.session.via = 'local';

    return res.redirect('/');
  } catch (err) {
    console.error('[nts-sso] local login error', err);
    return res.status(500).type('html').send(renderLogin({ error: 'Something went wrong. Please try again.' }));
  }
});

// Kick off the CRM redirect. A one-time state value is stashed in this
// browser's session and appended to the returnUrl so /auth/sso can confirm
// the token that comes back belongs to a login this same browser started
// (confirmed with NTS: they echo extra returnUrl query params back unchanged) —
// otherwise anyone with a validly-signed token (even their own) could plant
// it into a victim's browser and log the victim into the wrong account.
app.get('/auth/nts', (req, res) => {
  const state = crypto.randomUUID();
  req.session.ssoState = state;
  const returnUrl = `${RETURN_URL}?state=${encodeURIComponent(state)}`;
  const url = `${CRM_LOGIN_URL}?returnUrl=${encodeURIComponent(returnUrl)}`;
  res.redirect(url);
});

// CRM sends the user back here with ?token=<JWT>&state=<the value we sent>.
app.get(CALLBACK_PATH, async (req, res) => {
  const { token, state } = req.query;

  const expectedState = req.session.ssoState;
  delete req.session.ssoState;
  if (!expectedState || state !== expectedState) {
    console.warn('[nts-sso] SSO state mismatch — rejecting to prevent a planted-token login');
    return res.status(401).type('html').send(renderLogin({ error: 'Your sign-in session expired or is invalid. Please try again.' }));
  }

  if (!token) {
    return res.status(400).type('html').send(renderLogin({ error: 'Missing SSO token.' }));
  }

  let payload;
  try {
    payload = jwt.verify(token, NTS_JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: NTS_JWT_ISSUER,
      audience: NTS_JWT_AUDIENCE,
    });
  } catch (err) {
    console.error('[nts-sso] JWT verification failed', err.message);
    return res.status(401).type('html').send(renderLogin({ error: 'SSO verification failed. Please try again.' }));
  }

  const email = payload.email;
  if (!email) {
    return res.status(400).type('html').send(renderLogin({ error: 'SSO token did not include an email address.' }));
  }

  pruneUsedTokenIds();
  if (payload.jti) {
    if (usedTokenIds.has(payload.jti)) {
      console.warn('[nts-sso] rejected replayed SSO token', { jti: payload.jti, email });
      return res.status(401).type('html').send(renderLogin({ error: 'This sign-in link has already been used. Please sign in again.' }));
    }
    usedTokenIds.set(payload.jti, payload.exp || Date.now() / 1000 + 300);
  }

  // Policy: any valid NTS CRM user may sign in. If no matching Open WebUI
  // account exists yet, Open WebUI's trusted-header auth creates one
  // automatically on the next proxied request (see WEBUI_AUTH_TRUSTED_EMAIL_HEADER
  // in the Open WebUI docs). No extra action needed here.
  req.session.email = email;
  req.session.name = payload.name || email;
  req.session.via = 'nts-crm';

  return res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ── Reverse proxy everything else to Open WebUI, attaching the
//    trusted-identity headers once a session exists ──────────────────

const webuiProxy = createProxyMiddleware({
  target: OPEN_WEBUI_INTERNAL_URL,
  changeOrigin: true,
  ws: true, // Open WebUI uses websockets for streaming/chat
  onProxyReq: (proxyReq, req) => {
    proxyReq.setHeader(TRUSTED_EMAIL_HEADER, sanitizeHeaderValue(req.session.email));
    proxyReq.setHeader(TRUSTED_NAME_HEADER, sanitizeHeaderValue(req.session.name || req.session.email));
  },
  // No onProxyReqWs here: the WebSocket upgrade event bypasses Express's
  // middleware stack entirely (no cookie-parser/session ran on it), so
  // req.session doesn't exist on it — Open WebUI's own cookie, already
  // issued to the browser from the first trusted-header HTTP request,
  // authenticates the socket instead. Worth confirming this holds once
  // testing against the real Open WebUI instance.
});

app.use('/', requireSession, webuiProxy);

const server = app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[nts-sso] middleware listening on :${PORT}`);
  console.log(`[nts-sso] public URL: ${APP_PUBLIC_URL}`);
  console.log(`[nts-sso] proxying to: ${OPEN_WEBUI_INTERNAL_URL}`);
  console.log(`[nts-sso] CRM callback: ${RETURN_URL}`);
});

// http-proxy-middleware's automatic upgrade-event wiring isn't reliable
// behind an extra reverse-proxy hop (Coolify/Traefik) — wire it explicitly
// so WebSocket upgrades (chat streaming) actually reach Open WebUI instead
// of proxying to an undefined target.
server.on('upgrade', webuiProxy.upgrade);
