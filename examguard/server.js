// ExamGuard-style proctoring backend.
// Deliberately zero external dependencies (Node built-ins only) so it runs
// anywhere with just `node server.js` — no npm install required.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 8787;
const DATA_FILE = path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------- Persistence ----------

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const seed = { exams: {}, attempts: {}, users: {} };
    fs.writeFileSync(DATA_FILE, JSON.stringify(seed, null, 2));
    return seed;
  }
  const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!data.users) data.users = {}; // migrate older data.json files
  return data;
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let db = loadData();
function persist() { saveData(db); }

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

// ---------- Auth ----------
// Password hashing: Node's built-in scrypt (no bcrypt dependency needed).
// Sessions: a signed, stateless cookie (HMAC-SHA256) — no server-side
// session table, so no cleanup job needed. The signing secret is generated
// once and persisted to disk so restarting the server doesn't log everyone
// out during development.

const SECRET_FILE = path.join(__dirname, '.session-secret');
function loadOrCreateSecret() {
  if (fs.existsSync(SECRET_FILE)) return fs.readFileSync(SECRET_FILE, 'utf8').trim();
  const secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, secret);
  return secret;
}
const SESSION_SECRET = loadOrCreateSecret();
const SESSION_MAX_AGE_SEC = 60 * 60 * 12; // 12 hours

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  // constant-time compare
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function base64url(buf) { return Buffer.from(buf).toString('base64url'); }

function signToken(payload) {
  const body = base64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

// In production (behind HTTPS), mark the cookie Secure so browsers refuse
// to send it over a plain http:// connection. Skipped in local dev since
// localhost usually isn't served over HTTPS. Set NODE_ENV=production on
// your host (Render/Railway both do this automatically) to enable it.
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

function setSessionCookie(res, userId) {
  const token = signToken({ uid: userId, exp: Date.now() + SESSION_MAX_AGE_SEC * 1000 });
  const secure = IS_PRODUCTION ? '; Secure' : '';
  res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_MAX_AGE_SEC}${secure}`);
}
function clearSessionCookie(res) {
  const secure = IS_PRODUCTION ? '; Secure' : '';
  res.setHeader('Set-Cookie', `session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`);
}

function currentUser(req) {
  const cookies = parseCookies(req);
  const payload = verifyToken(cookies.session);
  if (!payload) return null;
  const user = db.users[payload.uid];
  if (!user) return null;
  return user;
}

function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role, matric: u.matric || null };
}

// ---------- Domain logic ----------

// Event types that are purely informational (shown in the timeline / flags
// feed) versus ones that count against the warning limit. Kept explicit and
// separate so we never silently double-count a single real-world incident
// (e.g. a fullscreen exit also fires a focus-loss and a visibility event in
// some browsers — only the fullscreen exit itself is a countable violation).
const COUNTABLE_EVENT_TYPES = new Set([
  'fullscreen_exit',
  'tab_switch',
  'multiple_session_attempt',
]);

const FLAG_CATEGORY_BY_EVENT = {
  tab_switch: 'Tab switch',
  fullscreen_exit: 'Fullscreen exit',
  multiple_session_attempt: 'Multiple session attempt',
  connection_loss: 'Connection problem',
  repeated_suspicious_activity: 'Repeated suspicious activity',
  auto_termination: 'Automatic termination',
};

function getExam(examId) {
  return db.exams[examId] || null;
}

function getAttempt(attemptId) {
  return db.attempts[attemptId] || null;
}

// A lecturer may access an attempt only for an exam they created; a student
// may access only their own attempt.
function canAccessAttempt(attempt, exam, user) {
  if (!attempt || !exam || !user) return false;
  if (user.role === 'lecturer') return exam.createdBy === user.id;
  return attempt.studentUserId === user.id;
}

function nowIso() {
  return new Date().toISOString();
}

function examDurationMs(exam) {
  return (exam.durationMinutes || 60) * 60 * 1000;
}

function attemptDeadline(attempt, exam) {
  return new Date(attempt.startedAt).getTime() + examDurationMs(exam);
}

function isAttemptExpired(attempt, exam) {
  return Date.now() > attemptDeadline(attempt, exam);
}

// Applies a monitoring event to an attempt: logs it, decides whether it's a
// countable violation, increments warnings, and — only when the lecturer has
// configured autoTermination and the configured warningLimit is reached —
// terminates the attempt. Every step here corresponds to something that
// actually happened client-side; nothing here fabricates a detection.
function recordEvent(attempt, exam, type, details) {
  const event = { id: id('evt'), type, details: details || null, timestamp: nowIso() };
  attempt.events.push(event);

  let warningIssued = null;
  let terminated = false;

  if (attempt.status === 'active' && COUNTABLE_EVENT_TYPES.has(type) && exam.controls.automaticWarningSystem) {
    attempt.warnings += 1;
    warningIssued = attempt.warnings;
    attempt.events.push({
      id: id('evt'),
      type: 'warning_issued',
      details: { count: attempt.warnings, limit: exam.warningLimit, cause: type },
      timestamp: nowIso(),
    });

    if (
      exam.controls.automaticTermination &&
      exam.warningLimit !== null &&
      attempt.warnings >= exam.warningLimit
    ) {
      terminateAttempt(attempt, exam, 'warning_limit_reached');
      terminated = true;
    }
  }

  persist();
  return { event, warningIssued, terminated, attempt };
}

function terminateAttempt(attempt, exam, reason) {
  attempt.status = 'terminated';
  attempt.submittedAt = nowIso();
  attempt.terminationReason = reason;
  attempt.events.push({
    id: id('evt'),
    type: 'auto_termination',
    details: { reason, warnings: attempt.warnings, limit: exam.warningLimit },
    timestamp: nowIso(),
  });
}

// ---------- HTTP plumbing ----------

function send(res, status, body, headers) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, headers || {}));
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = '';
    req.on('data', (c) => { chunks += c; if (chunks.length > 2_000_000) req.destroy(); });
    req.on('end', () => {
      if (!chunks) return resolve({});
      try { resolve(JSON.parse(chunks)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.join(PUBLIC_DIR, filePath);
  if (!filePath.startsWith(PUBLIC_DIR)) return send(res, 403, { error: 'forbidden' });
  fs.readFile(filePath, (err, content) => {
    if (err) return send(res, 404, { error: 'not found' });
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(content);
  });
}

// ---------- Routes ----------

async function handleApi(req, res, parsed) {
  const parts = parsed.pathname.split('/').filter(Boolean); // ['api', ...]
  const method = req.method;
  const me = currentUser(req);

  function requireAuth() {
    if (!me) { send(res, 401, { error: 'You need to be signed in.' }); return null; }
    return me;
  }
  function requireRole(role) {
    const u = requireAuth();
    if (!u) return null;
    if (u.role !== role) { send(res, 403, { error: `This action requires a ${role} account.` }); return null; }
    return u;
  }

  try {
    // ---- Auth ----

    // POST /api/auth/register  { email, password, role, name, matric }
    if (method === 'POST' && parts[1] === 'auth' && parts[2] === 'register') {
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const role = body.role === 'lecturer' ? 'lecturer' : 'student';
      if (!email || !body.password || !body.name) return send(res, 400, { error: 'Name, email and password are required.' });
      if (body.password.length < 8) return send(res, 400, { error: 'Password must be at least 8 characters.' });
      if (role === 'student' && !body.matric) return send(res, 400, { error: 'Matric number is required for student accounts.' });
      const exists = Object.values(db.users).find((u) => u.email === email);
      if (exists) return send(res, 409, { error: 'An account with this email already exists.' });
      const userId = id('user');
      const user = {
        id: userId, email, passwordHash: hashPassword(body.password),
        role, name: body.name, matric: role === 'student' ? body.matric : null,
        createdAt: nowIso(),
      };
      db.users[userId] = user;
      persist();
      setSessionCookie(res, userId);
      return send(res, 201, publicUser(user));
    }

    // POST /api/auth/login  { email, password }
    if (method === 'POST' && parts[1] === 'auth' && parts[2] === 'login') {
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const user = Object.values(db.users).find((u) => u.email === email);
      if (!user || !verifyPassword(body.password || '', user.passwordHash)) {
        return send(res, 401, { error: 'Incorrect email or password.' });
      }
      setSessionCookie(res, user.id);
      return send(res, 200, publicUser(user));
    }

    // POST /api/auth/logout
    if (method === 'POST' && parts[1] === 'auth' && parts[2] === 'logout') {
      clearSessionCookie(res);
      return send(res, 200, { ok: true });
    }

    // GET /api/auth/me
    if (method === 'GET' && parts[1] === 'auth' && parts[2] === 'me') {
      if (!me) return send(res, 401, { error: 'not signed in' });
      return send(res, 200, publicUser(me));
    }

    // POST /api/exams
    if (method === 'POST' && parts[1] === 'exams' && parts.length === 2) {
      const user = requireRole('lecturer');
      if (!user) return;
      const body = await readBody(req);
      const examId = id('exam');
      const exam = {
        id: examId,
        createdBy: user.id,
        course: body.course || 'Untitled course',
        title: body.title || 'Untitled examination',
        durationMinutes: Number(body.durationMinutes) || 60,
        securityLevel: body.securityLevel || 'standard', // standard | monitored | proctored
        controls: Object.assign({
          fullscreenRequired: false,
          tabSwitchDetection: false,
          focusLossDetection: false,
          cameraPermission: false,
          micPermission: false,
          activityLogging: true,
          automaticWarningSystem: true,
          automaticTermination: false,
        }, body.controls || {}),
        warningLimit: body.warningLimit === 'none' ? null : Number(body.warningLimit ?? 3),
        immediateResults: !!body.immediateResults,
        questions: Array.isArray(body.questions) && body.questions.length
          ? body.questions
          : [
              { id: 'q1', prompt: 'A gram-positive coccus in clusters is most likely which organism?' },
              { id: 'q2', prompt: 'Name the culture medium selective for Salmonella and Shigella.' },
              { id: 'q3', prompt: 'Describe the mechanism of action of beta-lactam antibiotics.' },
            ],
        createdAt: nowIso(),
      };
      db.exams[examId] = exam;
      persist();
      return send(res, 201, exam);
    }

    // GET /api/exams
    if (method === 'GET' && parts[1] === 'exams' && parts.length === 2) {
      if (!requireAuth()) return;
      const all = Object.values(db.exams).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const visible = me.role === 'lecturer' ? all.filter((e) => e.createdBy === me.id) : all;
      return send(res, 200, visible);
    }

    // GET /api/exams/:id
    if (method === 'GET' && parts[1] === 'exams' && parts.length === 3) {
      if (!requireAuth()) return;
      const exam = getExam(parts[2]);
      if (!exam) return send(res, 404, { error: 'exam not found' });
      return send(res, 200, exam);
    }

    // GET /api/exams/:id/live
    if (method === 'GET' && parts[1] === 'exams' && parts[3] === 'live') {
      const exam = getExam(parts[2]);
      if (!exam) return send(res, 404, { error: 'exam not found' });
      if (!requireRole('lecturer')) return;
      if (exam.createdBy !== me.id) return send(res, 403, { error: 'You can only monitor examinations you created.' });
      const attempts = Object.values(db.attempts).filter((a) => a.examId === exam.id);
      const rows = attempts.map((a) => summarizeAttemptRow(a, exam));
      return send(res, 200, {
        exam: { id: exam.id, course: exam.course, title: exam.title },
        studentsActive: attempts.filter((a) => a.status === 'active').length,
        studentsSubmitted: attempts.filter((a) => a.status === 'submitted' || a.status === 'terminated').length,
        studentsWithFlags: attempts.filter((a) => a.warnings > 0).length,
        rows,
      });
    }

    // GET /api/exams/:id/flags
    if (method === 'GET' && parts[1] === 'exams' && parts[3] === 'flags') {
      const exam = getExam(parts[2]);
      if (!exam) return send(res, 404, { error: 'exam not found' });
      if (!requireRole('lecturer')) return;
      if (exam.createdBy !== me.id) return send(res, 403, { error: 'You can only view flags for examinations you created.' });
      const attempts = Object.values(db.attempts).filter((a) => a.examId === exam.id);
      const flags = [];
      for (const a of attempts) {
        for (const ev of a.events) {
          if (FLAG_CATEGORY_BY_EVENT[ev.type]) {
            flags.push({
              flagId: ev.id,
              category: FLAG_CATEGORY_BY_EVENT[ev.type],
              student: a.student,
              matric: a.matric,
              attemptId: a.id,
              timestamp: ev.timestamp,
              details: ev.details,
              reviewed: !!ev.reviewed,
              lecturerNotes: ev.lecturerNotes || '',
            });
          }
        }
      }
      flags.sort((x, y) => y.timestamp.localeCompare(x.timestamp));
      return send(res, 200, flags);
    }

    // GET /api/exams/:id/analytics
    if (method === 'GET' && parts[1] === 'exams' && parts[3] === 'analytics') {
      const exam = getExam(parts[2]);
      if (!exam) return send(res, 404, { error: 'exam not found' });
      if (!requireRole('lecturer')) return;
      if (exam.createdBy !== me.id) return send(res, 403, { error: 'You can only view analytics for examinations you created.' });
      const attempts = Object.values(db.attempts).filter((a) => a.examId === exam.id);
      const count = (type) => attempts.reduce((n, a) => n + a.events.filter((e) => e.type === type).length, 0);
      return send(res, 200, {
        totalStudents: attempts.length,
        active: attempts.filter((a) => a.status === 'active').length,
        submitted: attempts.filter((a) => a.status === 'submitted').length,
        withWarnings: attempts.filter((a) => a.warnings > 0).length,
        withNoFlags: attempts.filter((a) => a.warnings === 0).length,
        tabSwitchEvents: count('tab_switch'),
        fullscreenExitEvents: count('fullscreen_exit'),
        terminatedExams: attempts.filter((a) => a.status === 'terminated').length,
      });
    }

    // PATCH /api/flags/:attemptId/:eventId  { reviewed, lecturerNotes }
    if (method === 'PATCH' && parts[1] === 'flags' && parts.length === 4) {
      const attempt = getAttempt(parts[2]);
      if (!attempt) return send(res, 404, { error: 'attempt not found' });
      const exam = getExam(attempt.examId);
      if (!requireRole('lecturer')) return;
      if (!exam || exam.createdBy !== me.id) return send(res, 403, { error: 'You can only review flags for examinations you created.' });
      const ev = attempt.events.find((e) => e.id === parts[3]);
      if (!ev) return send(res, 404, { error: 'event not found' });
      const body = await readBody(req);
      if (typeof body.reviewed === 'boolean') ev.reviewed = body.reviewed;
      if (typeof body.lecturerNotes === 'string') ev.lecturerNotes = body.lecturerNotes;
      persist();
      return send(res, 200, ev);
    }

    // POST /api/attempts  { examId, integrityAccepted }
    // Student identity (name/matric) always comes from the authenticated
    // account, never from the request body — otherwise a student could
    // start an attempt "as" someone else.
    if (method === 'POST' && parts[1] === 'attempts' && parts.length === 2) {
      const user = requireRole('student');
      if (!user) return;
      const body = await readBody(req);
      const exam = getExam(body.examId);
      if (!exam) return send(res, 404, { error: 'exam not found' });

      const existing = Object.values(db.attempts).find(
        (a) => a.examId === exam.id && a.studentUserId === user.id && a.status === 'active'
      );
      if (existing) {
        // Section 5 / 18: detect + flag, never silently spin up a second
        // attempt. Let the student reconnect to the one that's active.
        recordEvent(existing, exam, 'multiple_session_attempt', { note: 'second start request while attempt active' });
        return send(res, 200, { reconnected: true, attempt: existing, exam });
      }

      const finished = Object.values(db.attempts).find(
        (a) => a.examId === exam.id && a.studentUserId === user.id && a.status !== 'active'
      );
      if (finished) {
        return send(res, 409, { error: 'This examination attempt has already been completed and cannot be restarted.' });
      }

      if (exam.securityLevel === 'proctored' && !body.integrityAccepted) {
        return send(res, 400, { error: 'The academic integrity declaration must be accepted before starting.' });
      }

      const attemptId = id('att');
      const attempt = {
        id: attemptId,
        examId: exam.id,
        studentUserId: user.id,
        student: user.name,
        matric: user.matric || 'N/A',
        status: 'active',
        integrityAccepted: !!body.integrityAccepted,
        startedAt: nowIso(),
        submittedAt: null,
        terminationReason: null,
        warnings: 0,
        answers: {},
        events: [{ id: id('evt'), type: 'exam_started', details: null, timestamp: nowIso() }],
      };
      db.attempts[attemptId] = attempt;
      persist();
      return send(res, 201, { reconnected: false, attempt, exam });
    }

    // GET /api/attempts/:id
    if (method === 'GET' && parts[1] === 'attempts' && parts.length === 3) {
      const attempt = getAttempt(parts[2]);
      if (!attempt) return send(res, 404, { error: 'attempt not found' });
      const exam = getExam(attempt.examId);
      if (!requireAuth()) return;
      if (!canAccessAttempt(attempt, exam, me)) return send(res, 403, { error: 'You do not have access to this attempt.' });
      return send(res, 200, { attempt, exam });
    }

    // GET /api/attempts/:id/timeline
    if (method === 'GET' && parts[1] === 'attempts' && parts[3] === 'timeline') {
      const attempt = getAttempt(parts[2]);
      if (!attempt) return send(res, 404, { error: 'attempt not found' });
      const exam = getExam(attempt.examId);
      if (!requireAuth()) return;
      if (!canAccessAttempt(attempt, exam, me)) return send(res, 403, { error: 'You do not have access to this attempt.' });
      const timeline = attempt.events
        .slice()
        .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
        .map((e) => ({ ...e, label: describeEvent(e) }));
      return send(res, 200, timeline);
    }

    // POST /api/attempts/:id/answer  { questionId, answer }
    if (method === 'POST' && parts[1] === 'attempts' && parts[3] === 'answer') {
      const attempt = getAttempt(parts[2]);
      if (!attempt) return send(res, 404, { error: 'attempt not found' });
      const exam = getExam(attempt.examId);
      if (!requireRole('student')) return;
      if (attempt.studentUserId !== me.id) return send(res, 403, { error: 'This is not your attempt.' });
      if (attempt.status !== 'active') return send(res, 409, { error: 'attempt is not active' });
      if (isAttemptExpired(attempt, exam)) {
        closeExpiredAttempt(attempt, exam);
        return send(res, 410, { error: 'The examination period has ended.', attempt });
      }
      const body = await readBody(req);
      attempt.answers[body.questionId] = body.answer;
      attempt.events.push({ id: id('evt'), type: 'answer_changed', details: { questionId: body.questionId }, timestamp: nowIso() });
      persist();
      return send(res, 200, { attempt });
    }

    // POST /api/attempts/:id/event  { type, details }
    if (method === 'POST' && parts[1] === 'attempts' && parts[3] === 'event') {
      const attempt = getAttempt(parts[2]);
      if (!attempt) return send(res, 404, { error: 'attempt not found' });
      const exam = getExam(attempt.examId);
      if (!requireRole('student')) return;
      if (attempt.studentUserId !== me.id) return send(res, 403, { error: 'This is not your attempt.' });
      if (attempt.status !== 'active') return send(res, 200, { attempt, terminated: attempt.status === 'terminated' });
      if (isAttemptExpired(attempt, exam)) {
        closeExpiredAttempt(attempt, exam);
        return send(res, 200, { attempt, terminated: false, expired: true });
      }
      const body = await readBody(req);
      const result = recordEvent(attempt, exam, body.type, body.details);
      return send(res, 200, result);
    }

    // POST /api/attempts/:id/submit
    if (method === 'POST' && parts[1] === 'attempts' && parts[3] === 'submit') {
      const attempt = getAttempt(parts[2]);
      if (!attempt) return send(res, 404, { error: 'attempt not found' });
      const exam = getExam(attempt.examId);
      if (!requireRole('student')) return;
      if (attempt.studentUserId !== me.id) return send(res, 403, { error: 'This is not your attempt.' });
      if (attempt.status === 'active') {
        attempt.status = 'submitted';
        attempt.submittedAt = nowIso();
        attempt.events.push({ id: id('evt'), type: 'exam_submitted', details: null, timestamp: nowIso() });
        persist();
      }
      return send(res, 200, { attempt, exam });
    }

    return send(res, 404, { error: 'unknown endpoint' });
  } catch (err) {
    return send(res, 500, { error: 'server error', message: String(err && err.message || err) });
  }
}

function closeExpiredAttempt(attempt, exam) {
  attempt.status = 'submitted';
  attempt.submittedAt = nowIso();
  attempt.terminationReason = 'exam_expired';
  attempt.events.push({ id: id('evt'), type: 'exam_expired', details: null, timestamp: nowIso() });
  persist();
}

function summarizeAttemptRow(attempt, exam) {
  const lastEvent = attempt.events[attempt.events.length - 1];
  let status = '🟢 Live';
  if (attempt.status === 'terminated') status = '🔴 Terminated';
  else if (attempt.status === 'submitted') status = '⚪ Submitted';
  else if (attempt.warnings > 0) status = '🟡 Warning';

  const remainingMs = attempt.status === 'active' ? Math.max(0, attemptDeadline(attempt, exam) - Date.now()) : null;

  return {
    attemptId: attempt.id,
    student: attempt.student,
    matric: attempt.matric,
    status,
    rawStatus: attempt.status,
    timeRemainingSec: remainingMs === null ? null : Math.floor(remainingMs / 1000),
    warnings: attempt.warnings,
    warningLimit: exam.warningLimit,
    lastActivity: lastEvent ? describeEvent(lastEvent) : 'Normal',
  };
}

function describeEvent(e) {
  const map = {
    exam_started: 'Exam started',
    answer_changed: 'Answer changed',
    tab_switch: 'Tab switch',
    fullscreen_exit: 'Fullscreen exited',
    fullscreen_restored: 'Fullscreen restored',
    focus_loss: 'Browser focus lost',
    focus_regain: 'Browser focus regained',
    connection_loss: 'Connection lost',
    connection_recovery: 'Connection restored',
    multiple_session_attempt: 'Multiple session attempt',
    warning_issued: 'Warning issued',
    auto_termination: 'Automatically terminated',
    exam_submitted: 'Examination submitted',
    exam_expired: 'Examination period ended',
  };
  return map[e.type] || e.type;
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname.startsWith('/api/')) {
    return handleApi(req, res, parsed);
  }
  return serveStatic(req, res, parsed.pathname);
});

server.listen(PORT, () => {
  console.log(`ExamGuard prototype running at http://localhost:${PORT}`);
});
