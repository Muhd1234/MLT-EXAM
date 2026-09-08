# Invigil — Examination Security Prototype

A working scaffold of the proctoring/security layer described in the spec:
proctored exam mode, camera/mic permission checks, fullscreen enforcement,
activity monitoring, a configurable warning system, automatic termination,
a live lecturer dashboard, a flags feed, and per-attempt timelines.

No external dependencies — Node.js built-ins only, so there's nothing to
`npm install`.

## Run it

```
node server.js
```

Then open **http://localhost:8787** in a browser. Register an account —
choose Lecturer or Student — then log in. Each account only sees its own
world: lecturers only see exams they created; students only see and can act
on their own attempts.

## Try the full flow

1. Register a **lecturer** account. Go to **New examination**, pick a
   security level (Standard / Monitored / Proctored) — this pre-fills
   sensible controls, which you can still hand-tune. Set the warning limit
   and create the exam.
2. Open a second browser (or an incognito window — session cookies mean one
   browser can only be logged in as one account at a time) and register a
   **student** account.
3. As the student, pick the exam and go through: identity confirmation →
   system check (camera/mic/fullscreen/connection, for proctored exams) →
   integrity declaration → the exam itself.
4. While taking the exam, exit fullscreen or switch tabs — you'll see real
   warnings fire (these are genuine `fullscreenchange` / `visibilitychange`
   browser events, not simulated). Reach the configured warning limit and
   the attempt auto-terminates, exactly as configured by the lecturer.
5. Back in the lecturer's **Live monitoring** tab, watch the student's row
   update (polls every 4s), then check **Flags** and a **Timeline** for the
   specific attempt.

## What's real vs. simplified

- **Real:** email/password accounts with salted, hashed passwords
  (`crypto.scrypt`, no bcrypt dependency needed), signed session cookies
  (`crypto.createHmac`, no JWT library needed), and per-request
  authorization — a student can only read/act on their own attempt, a
  lecturer can only see exams they created. Identity (name, matric) always
  comes from the session, never from anything the client sends, so a
  student can't start an attempt "as" someone else.
- **Real:** fullscreen enforcement, tab-visibility detection, focus-loss
  detection, online/offline detection, the warning/termination state
  machine, duplicate-session blocking (a student can't spin up a second
  attempt — they reconnect to the active one, scoped to their own account),
  exam-expiry auto-submit, local answer caching while offline with sync on
  reconnect.
- **Real but minimal by design:** camera/microphone are only ever checked
  for *permission* via `getUserMedia`, then the stream is stopped
  immediately. Nothing is recorded, transmitted, or stored — per the "no
  secret monitoring, no unnecessary data collection" requirement in the
  spec. If you want continuous identity verification beyond a permission
  check, that's a deliberate scope decision to revisit with your
  institution's legal/privacy sign-off first.
- **Simplified for a prototype:** no email verification or password reset
  flow, no scoring engine (completion screen shows "pending" rather than a
  real grade), data is stored in a single `data.json` file rather than a
  real database, single Node process (no clustering), session secret lives
  in a plain file (`.session-secret`, auto-generated on first run — fine
  for local dev, not for production).

## Where things live

- `server.js` — all API routes, auth (`hashPassword`/`verifyPassword`,
  `signToken`/`verifyToken`, session cookies), and the warning/termination
  logic (search for `recordEvent` and `terminateAttempt`).
- `public/app.js` — routing (with auth-aware route guards in `route()`),
  login/register views, all other views, and the browser-level monitors
  (search for `attachMonitors`).
- `public/styles.css` — design tokens at the top (`:root`).
- `data.json` — flat-file store (exams, attempts, users), safe to delete
  to reset all data. `.session-secret` is generated alongside it — delete
  both together, or deleting just the secret logs everyone out.

## Deploying

- A `.gitignore` is included — `data.json` and `.session-secret` are
  excluded on purpose since they hold real user data and your signing
  secret. Don't commit them.
- Set `NODE_ENV=production` on your host and the session cookie
  automatically gets the `Secure` flag (browsers then refuse to send it
  over plain HTTP). Locally, leave `NODE_ENV` unset so cookies still work
  over `http://localhost`.
- `server.js` already reads `process.env.PORT`, so it works as-is on
  platforms like Render or Railway that assign a port for you.
- Whatever host you use, make sure `data.json` and `.session-secret` live
  on **persistent** storage — on most platforms a redeploy wipes any file
  that isn't on a mounted disk, which would delete every account and exam.

## Extending this into your real platform

The monitoring/warning/termination engine (`recordEvent` in `server.js`) is
intentionally decoupled from storage — swap `data.json` for a real database
by replacing `loadData`/`saveData`/`persist` and the logic underneath stays
the same. Same for auth: `hashPassword`/`verifyPassword`/`signToken` don't
care where users are stored, so swapping in a real user table (or an
existing SSO/identity provider) means replacing the lookups in
`currentUser()`, `/auth/register`, and `/auth/login` — the session-cookie
mechanism and the `requireAuth`/`requireRole` guards on every route can
stay as-is. The frontend monitors (`attachMonitors` in `app.js`) are plain
browser APIs and will drop into any framework (React, Vue, etc.) if you
later want to merge this into an existing app rather than run it
standalone.
