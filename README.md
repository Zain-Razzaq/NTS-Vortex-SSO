# Vortex SSO Middleware

Bridges NTS CRM's custom JWT-redirect SSO with Open WebUI's trusted-header
authentication, and serves a login page with both:
- Email/password (proxied to Open WebUI's own login)
- "Sign in with NTS CRM"

## How it works

```
Browser → vortex.ntsconnect.com → [this middleware]
                                        │
                    (no session) → /login page
                    (has session) → proxies to Open WebUI internally,
                                     attaching X-User-Email header
```

Open WebUI itself becomes **internal-only** — no public domain, reachable
only from this middleware over Coolify's internal Docker network.

## Setup in Coolify

### 1. Deploy this as a new service
- New "Application" in Coolify, pointing at this repo/folder (Dockerfile included).
- Put it on the **same project/network** as your existing Open WebUI service,
  so it can reach it internally.

### 2. Move the public domain
- Remove `vortex.ntsconnect.com` from the Open WebUI service in Coolify.
- Add `vortex.ntsconnect.com` as the public domain on **this middleware
  service** instead.

### 3. Set Open WebUI to internal-only + trusted header
On the **Open WebUI** service, in its compose file's `environment:` section
(same place you added `GOOGLE_CLIENT_ID` etc. earlier — Coolify only passes
through variables referenced there):

```yaml
environment:
  - WEBUI_AUTH_TRUSTED_EMAIL_HEADER=X-User-Email
  - WEBUI_AUTH_TRUSTED_NAME_HEADER=X-User-Name
  - ENABLE_LOGIN_FORM=false
  - ENABLE_SIGNUP=false
  - WEBUI_URL=https://vortex.ntsconnect.com
```

`ENABLE_LOGIN_FORM=false` is safe here — **all** logins (local password and
NTS CRM) now go through the middleware's own login page instead.

Also make sure Open WebUI has no direct public route (no FQDN assigned to
it in Coolify) — it should only be reachable via its internal service name
(e.g. `open-webui`) on its internal port (`8080`), which is what
`OPEN_WEBUI_INTERNAL_URL` below points at.

### 4. Set new-user defaults in Open WebUI (important)
Since NTS CRM logins now **auto-create** an Open WebUI account when the
email doesn't exist yet, decide what role those new accounts get by
default. Open WebUI's `DEFAULT_USER_ROLE` controls this — it's commonly
`pending` by default, which would require an admin to manually approve
every new teammate before they can use the app. If you want NTS CRM
logins to work immediately without manual approval, add this to Open
WebUI's compose `environment:` section too:

```yaml
  - DEFAULT_USER_ROLE=user
```

(Skip this if you're fine manually approving each new user in the Admin
Panel — safer if you want a review step, but adds friction for new hires.)

### 5. Set this middleware's environment variables in Coolify
Copy `.env.example` → fill in real values as Coolify env vars (see file for
descriptions of each):

- `APP_PUBLIC_URL=https://vortex.ntsconnect.com`
- `OPEN_WEBUI_INTERNAL_URL=http://open-webui:8080` (use your actual internal
  service name/port — check Coolify's service details)
- `CRM_LOGIN_URL=https://crm.ntsconnect.com/Account/Login`
- `NTS_JWT_SECRET=<the HS256 secret from Sajid>`
- `OPEN_WEBUI_ADMIN_API_KEY=<the key from step 4>`
- `SESSION_SECRET=<random string, e.g. output of: openssl rand -hex 32>`

### 6. Redeploy both services
Redeploy Open WebUI (for its new env vars) and this middleware.

### 7. Register the callback URL with NTS CRM (if needed)
Confirm with Sajid's team that `https://vortex.ntsconnect.com/auth/sso` is
an allowed `returnUrl` destination on their side (mirroring how
`sales.ntsconnect.com/auth/sso` is already allowed for Sales Tracker).

## Testing

1. Visit `https://vortex.ntsconnect.com` — should show the login page
   (not Open WebUI's own login, and not a 404).
2. Try local email/password with an existing Open WebUI account — should
   log in and land on the normal chat interface.
3. Click "Sign in with NTS CRM" — should redirect to `crm.ntsconnect.com`,
   then back to `vortex.ntsconnect.com`, logged in. If that email has no
   existing Open WebUI account, one is created automatically (check
   `DEFAULT_USER_ROLE` above for whether it needs admin approval first).
4. Try accessing Open WebUI's internal address directly (if reachable from
   your network) — it should **not** be reachable from outside; only the
   middleware should be public. This is the critical security check.

## Current policies (as configured)

- **NTS CRM logins auto-create an Open WebUI account** if the email
  doesn't have one yet (handled natively by Open WebUI's trusted-header
  auth — no extra code needed). See step 4 above for the new-account
  role/approval setting.
- **Accounts are matched by email** — an NTS CRM login with the same email
  as an existing local account logs into that same account.
- Session lasts 12 hours (`cookie.maxAge` in `server.js`), then the user
  needs to log in again.

## Local development

```bash
npm install
cp .env.example .env   # fill in real values
npm start
```
