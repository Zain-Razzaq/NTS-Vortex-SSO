require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');

// ── Config (fail loudly if something critical is missing) ────────────
const {
  APP_PUBLIC_URL,
  OPEN_WEBUI_INTERNAL_URL,
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

  try {
    const resp = await fetch(`${OPEN_WEBUI_INTERNAL_URL}/api/v1/auths/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!resp.ok) {
      return res.status(401).type('html').send(renderLogin({ error: 'Invalid email or password.' }));
    }

    const data = await resp.json();
    const confirmedEmail = data.email || email;

    req.session.email = confirmedEmail;
    req.session.name = data.name || confirmedEmail;
    req.session.via = 'local';

    return res.redirect('/');
  } catch (err) {
    console.error('[nts-sso] local login error', err);
    return res.status(500).type('html').send(renderLogin({ error: 'Something went wrong. Please try again.' }));
  }
});

// Kick off the CRM redirect.
app.get('/auth/nts', (req, res) => {
  const url = `${CRM_LOGIN_URL}?returnUrl=${encodeURIComponent(RETURN_URL)}`;
  res.redirect(url);
});

// CRM sends the user back here with ?token=<JWT>.
app.get(CALLBACK_PATH, async (req, res) => {
  const { token } = req.query;
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

app.use(
  '/',
  requireSession,
  createProxyMiddleware({
    target: OPEN_WEBUI_INTERNAL_URL,
    changeOrigin: true,
    ws: true, // Open WebUI uses websockets for streaming/chat
    onProxyReq: (proxyReq, req) => {
      proxyReq.setHeader(TRUSTED_EMAIL_HEADER, sanitizeHeaderValue(req.session.email));
      proxyReq.setHeader(TRUSTED_NAME_HEADER, sanitizeHeaderValue(req.session.name || req.session.email));
    },
  })
);

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[nts-sso] middleware listening on :${PORT}`);
  console.log(`[nts-sso] public URL: ${APP_PUBLIC_URL}`);
  console.log(`[nts-sso] proxying to: ${OPEN_WEBUI_INTERNAL_URL}`);
  console.log(`[nts-sso] CRM callback: ${RETURN_URL}`);
});
