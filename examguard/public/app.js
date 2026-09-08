// Invigil — proctoring prototype frontend. Vanilla JS, no build step.
// Every "detected" event below corresponds to a real browser API signal.
// Camera/microphone are only ever checked for permission + immediately
// stopped again — nothing is recorded or transmitted. See the explanation
// modal in showPermissionExplainer() for what we tell the student before we
// ask, per the "no secret monitoring" requirement.

const el = (sel, root = document) => root.querySelector(sel);
const app = el('#app');

const state = {
  route: '#/',
  examCache: {},
  currentUser: null, // populated by loadSession() before the first route()
};

async function api(path, opts) {
  const res = await fetch('/api' + path, Object.assign({
    headers: { 'Content-Type': 'application/json' },
  }, opts));
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) state.currentUser = null;
    throw Object.assign(new Error(body.error || 'Request failed'), { body, status: res.status });
  }
  return body;
}

function h(strings, ...vals) {
  return strings.reduce((out, s, i) => out + s + (vals[i] ?? ''), '');
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtClock(sec) {
  if (sec == null) return '—';
  const m = Math.floor(sec / 60).toString().padStart(2, '0');
  const s = Math.floor(sec % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ---------- Shell / router ----------

function renderShell(activeTop, bodyHtml, mainClass = '') {
  const u = state.currentUser;
  app.innerHTML = h`
    <div class="topbar">
      <div class="brand"><span class="mark">Invigil</span><span class="tag">examination security</span></div>
      <div class="topnav">
        ${u ? h`
          <span class="small" style="margin-right:10px;">${esc(u.name)} · ${u.role}</span>
          <button class="ghost" id="logoutBtn">Log out</button>
        ` : h`
          <button data-nav="#/login" class="${activeTop === 'login' ? 'active' : ''}">Log in</button>
          <button data-nav="#/register" class="${activeTop === 'register' ? 'active' : ''}">Register</button>
        `}
      </div>
    </div>
    <main class="${mainClass}">${bodyHtml}</main>
  `;
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
  if (el('#logoutBtn')) el('#logoutBtn').addEventListener('click', async () => {
    await api('/auth/logout', { method: 'POST' });
    state.currentUser = null;
    location.hash = '#/';
  });
}

window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', async () => {
  await loadSession();
  route();
});

async function loadSession() {
  try { state.currentUser = await api('/auth/me'); } catch { state.currentUser = null; }
}

function route() {
  const hash = location.hash || '#/';
  const parts = hash.replace('#/', '').split('/').filter(Boolean);
  const u = state.currentUser;

  if (parts[0] === 'login') return u ? goHome() : viewLogin();
  if (parts[0] === 'register') return u ? goHome() : viewRegister();

  if (parts[0] === 'lecturer') {
    if (!u) return viewLogin('Log in with a lecturer account to continue.');
    if (u.role !== 'lecturer') return viewLogin('This area is for lecturer accounts. Log in with a lecturer account to continue.');
    if (parts.length === 1) return viewLecturerHome();
    if (parts[1] === 'new') return viewCreateExam();
    if (parts[2] === 'live') return viewLiveDashboard(parts[1]);
    if (parts[2] === 'flags') return viewFlags(parts[1]);
    if (parts[2] === 'attempt' && parts[4] === 'timeline') return viewTimeline(parts[1], parts[3]);
  }

  if (parts[0] === 'student') {
    if (!u) return viewLogin('Log in with a student account to continue.');
    if (u.role !== 'student') return viewLogin('This area is for student accounts. Log in with a student account to continue.');
    if (parts.length === 1) return viewStudentHome();
    if (parts[1]) return viewStudentExam(parts[1]);
  }

  return viewHome();
}

function goHome() {
  const u = state.currentUser;
  location.hash = u ? (u.role === 'lecturer' ? '#/lecturer' : '#/student') : '#/';
}

function viewHome() {
  const u = state.currentUser;
  if (u) { goHome(); return; }
  renderShell('', h`
    <div class="panel stack" style="max-width:520px;margin:60px auto;text-align:center;">
      <h1>Invigil</h1>
      <p>A configurable examination security layer — proctored exam mode, live monitoring, warnings and flags.</p>
      <div class="row" style="justify-content:center;">
        <button data-nav="#/register">Create an account</button>
        <button class="secondary" data-nav="#/login">Log in</button>
      </div>
    </div>
  `, 'narrow');
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
}

// ---------- Auth views ----------

function viewLogin(notice) {
  renderShell('login', h`
    <div class="panel stack" style="max-width:400px;margin:60px auto;">
      <h1>Log in</h1>
      ${notice ? `<p class="hint">${esc(notice)}</p>` : ''}
      <form id="loginForm" class="stack">
        <div class="field"><label>Email</label><input name="email" type="text" required></div>
        <div class="field"><label>Password</label><input name="password" type="password" required></div>
        <div id="loginError" class="hint" style="color:var(--red);display:none;"></div>
        <button type="submit">Log in</button>
      </form>
      <p class="small">No account yet? <a href="#/register">Register</a></p>
    </div>
  `, 'narrow');
  el('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const errBox = el('#loginError');
    try {
      state.currentUser = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email: fd.get('email'), password: fd.get('password') }) });
      goHome();
    } catch (err) {
      errBox.textContent = err.body?.error || 'Could not log in.';
      errBox.style.display = 'block';
    }
  });
}

function viewRegister() {
  renderShell('register', h`
    <div class="panel stack" style="max-width:420px;margin:60px auto;">
      <h1>Create an account</h1>
      <form id="regForm" class="stack">
        <div class="field"><label>I am a…</label>
          <select name="role" id="roleSelect">
            <option value="student">Student</option>
            <option value="lecturer">Lecturer</option>
          </select>
        </div>
        <div class="field"><label>Full name</label><input name="name" type="text" required></div>
        <div class="field" id="matricField"><label>Matric number</label><input name="matric" type="text"></div>
        <div class="field"><label>Email</label><input name="email" type="text" required></div>
        <div class="field"><label>Password</label><input name="password" type="password" minlength="8" required><div class="hint">At least 8 characters.</div></div>
        <div id="regError" class="hint" style="color:var(--red);display:none;"></div>
        <button type="submit">Create account</button>
      </form>
      <p class="small">Already have an account? <a href="#/login">Log in</a></p>
    </div>
  `, 'narrow');

  const roleSelect = el('#roleSelect');
  const matricField = el('#matricField');
  function syncMatric() { matricField.style.display = roleSelect.value === 'student' ? 'block' : 'none'; }
  roleSelect.addEventListener('change', syncMatric);
  syncMatric();

  el('#regForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const errBox = el('#regError');
    try {
      state.currentUser = await api('/auth/register', { method: 'POST', body: JSON.stringify({
        role: fd.get('role'), name: fd.get('name'), matric: fd.get('matric'),
        email: fd.get('email'), password: fd.get('password'),
      })});
      goHome();
    } catch (err) {
      errBox.textContent = err.body?.error || 'Could not create account.';
      errBox.style.display = 'block';
    }
  });
}

// ---------- Lecturer: exam list ----------

async function viewLecturerHome() {
  renderShell('lecturer', `<div class="empty">Loading examinations…</div>`);
  const exams = await api('/exams');
  renderShell('lecturer', h`
    <div class="row" style="justify-content:space-between;margin-bottom:20px;">
      <h1>Examinations</h1>
      <button data-nav="#/lecturer/new">New examination</button>
    </div>
    <div class="stack">
      ${exams.length ? exams.map(examRow).join('') : `<div class="panel empty">No examinations yet. Create one to get started.</div>`}
    </div>
  `);
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
  app.querySelectorAll('[data-live]').forEach((b) => b.addEventListener('click', () => { location.hash = `#/lecturer/${b.dataset.live}/live`; }));
  app.querySelectorAll('[data-flags]').forEach((b) => b.addEventListener('click', () => { location.hash = `#/lecturer/${b.dataset.flags}/flags`; }));
}

function examRow(exam) {
  return h`
    <div class="panel row" style="justify-content:space-between;">
      <div>
        <div class="row" style="gap:10px;">
          <h3>${esc(exam.title)}</h3>
          <span class="badge ${exam.securityLevel}">${exam.securityLevel}</span>
        </div>
        <p class="small">${esc(exam.course)} · ${exam.durationMinutes} min · warning limit ${exam.warningLimit ?? 'none'}</p>
      </div>
      <div class="row">
        <button class="secondary" data-flags="${exam.id}">Flags</button>
        <button data-live="${exam.id}">Live monitoring</button>
      </div>
    </div>
  `;
}

// ---------- Lecturer: create exam (Section 13) ----------

function viewCreateExam() {
  renderShell('lecturer', h`
    <h1>New examination</h1>
    <p>Configure the security layer for this examination.</p>
    <form id="examForm" class="panel stack">
      <div class="grid-2">
        <div class="field"><label>Course</label><input name="course" type="text" placeholder="MLS 305 — Medical Microbiology" required></div>
        <div class="field"><label>Examination title</label><input name="title" type="text" placeholder="Mid-semester examination" required></div>
      </div>
      <div class="grid-2">
        <div class="field"><label>Duration (minutes)</label><input name="durationMinutes" type="number" value="45" min="5" required></div>
        <div class="field"><label>Warning limit</label>
          <select name="warningLimit">
            <option value="1">1</option><option value="2">2</option>
            <option value="3" selected>3</option><option value="4">4</option>
            <option value="5">5</option><option value="none">No automatic termination</option>
          </select>
        </div>
      </div>

      <div class="divider"></div>
      <h3>Security level</h3>
      <div class="field">
        <select name="securityLevel" id="securityLevel">
          <option value="standard">Standard — normal CBT, no monitoring</option>
          <option value="monitored">Monitored — activity logging, no camera/mic</option>
          <option value="proctored">Proctored — full monitoring + integrity declaration</option>
        </select>
      </div>

      <div class="divider"></div>
      <h3>Available controls</h3>
      <div id="controls">
        ${toggleRow('fullscreenRequired', 'Fullscreen required', 'Student must stay in fullscreen throughout the attempt')}
        ${toggleRow('tabSwitchDetection', 'Tab-switch detection', 'Flags when the student switches or hides the tab')}
        ${toggleRow('focusLossDetection', 'Focus-loss detection', 'Logs when the browser window loses focus (informational)')}
        ${toggleRow('cameraPermission', 'Camera permission', 'Confirms camera access is available — no video is recorded')}
        ${toggleRow('micPermission', 'Microphone permission', 'Confirms microphone access is available — no audio is recorded')}
        ${toggleRow('activityLogging', 'Activity logging', 'Keep a timestamped record of exam events', true)}
        ${toggleRow('automaticWarningSystem', 'Automatic warning system', 'Issue warnings to the student when a violation is detected', true)}
        ${toggleRow('automaticTermination', 'Automatic termination', 'End and submit the attempt once the warning limit is reached')}
      </div>

      <div class="divider"></div>
      <div class="row" style="justify-content:flex-end;">
        <button type="button" class="secondary" data-nav="#/lecturer">Cancel</button>
        <button type="submit">Create examination</button>
      </div>
    </form>
  `, 'narrow');

  const form = el('#examForm');
  const secSelect = el('#securityLevel');

  function applyPreset() {
    const preset = {
      standard: { fullscreenRequired: false, tabSwitchDetection: false, focusLossDetection: false, cameraPermission: false, micPermission: false, activityLogging: true, automaticWarningSystem: false, automaticTermination: false },
      monitored: { fullscreenRequired: true, tabSwitchDetection: true, focusLossDetection: true, cameraPermission: false, micPermission: false, activityLogging: true, automaticWarningSystem: true, automaticTermination: false },
      proctored: { fullscreenRequired: true, tabSwitchDetection: true, focusLossDetection: true, cameraPermission: true, micPermission: true, activityLogging: true, automaticWarningSystem: true, automaticTermination: true },
    }[secSelect.value];
    Object.entries(preset).forEach(([k, v]) => { const cb = form.querySelector(`[name=${k}]`); if (cb) cb.checked = v; });
  }
  secSelect.addEventListener('change', applyPreset);
  applyPreset();

  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const controls = {};
    ['fullscreenRequired','tabSwitchDetection','focusLossDetection','cameraPermission','micPermission','activityLogging','automaticWarningSystem','automaticTermination']
      .forEach((k) => { controls[k] = !!form.querySelector(`[name=${k}]`).checked; });
    const exam = await api('/exams', { method: 'POST', body: JSON.stringify({
      course: fd.get('course'), title: fd.get('title'),
      durationMinutes: fd.get('durationMinutes'), warningLimit: fd.get('warningLimit'),
      securityLevel: fd.get('securityLevel'), controls,
    })});
    location.hash = `#/lecturer/${exam.id}/live`;
  });
}

function toggleRow(name, label, sub, checked = false) {
  return h`
    <div class="toggle-row">
      <div><div class="label">${label}</div><div class="sub">${sub}</div></div>
      <label class="switch"><input type="checkbox" name="${name}" ${checked ? 'checked' : ''}><span class="track"></span></label>
    </div>
  `;
}

// ---------- Lecturer: live dashboard (Section 8, 19) ----------

let liveTimer = null;

async function viewLiveDashboard(examId) {
  clearInterval(liveTimer);
  renderShell('lecturer', `<div class="empty">Loading live monitoring…</div>`);

  async function refresh() {
    const [live, analytics] = await Promise.all([api(`/exams/${examId}/live`), api(`/exams/${examId}/analytics`)]);
    renderShell('lecturer', h`
      <div class="row" style="justify-content:space-between;">
        <div>
          <h1>Live examination</h1>
          <p>${esc(live.exam.course)} — ${esc(live.exam.title)}</p>
        </div>
        <div class="row">
          <button class="ghost" data-nav="#/lecturer">All exams</button>
          <button class="secondary" data-flags="${examId}">Flags</button>
        </div>
      </div>

      <div class="stat-row">
        <div class="stat"><div class="n">${live.studentsActive}</div><div class="l">Students active</div></div>
        <div class="stat"><div class="n">${live.studentsSubmitted}</div><div class="l">Students submitted</div></div>
        <div class="stat"><div class="n">${live.studentsWithFlags}</div><div class="l">Students with flags</div></div>
      </div>

      <table class="live">
        <thead><tr><th>Student</th><th>Matric No</th><th>Status</th><th>Time remaining</th><th>Warnings</th><th>Activity</th><th></th></tr></thead>
        <tbody>
          ${live.rows.length ? live.rows.map((r) => h`
            <tr>
              <td>${esc(r.student)}</td>
              <td class="small">${esc(r.matric)}</td>
              <td>${r.status}</td>
              <td>${fmtClock(r.timeRemainingSec)}</td>
              <td>${r.warnings}/${r.warningLimit ?? '∞'}</td>
              <td class="small">${esc(r.lastActivity)}</td>
              <td><button class="ghost" data-tl="${r.attemptId}">Timeline</button></td>
            </tr>
          `).join('') : `<tr><td colspan="7" class="empty">No students have started this examination yet.</td></tr>`}
        </tbody>
      </table>

      <div class="divider"></div>
      <h3>Analytics</h3>
      <div class="stat-row">
        <div class="stat"><div class="n">${analytics.totalStudents}</div><div class="l">Total students</div></div>
        <div class="stat"><div class="n">${analytics.tabSwitchEvents}</div><div class="l">Tab-switch events</div></div>
        <div class="stat"><div class="n">${analytics.fullscreenExitEvents}</div><div class="l">Fullscreen exits</div></div>
        <div class="stat"><div class="n">${analytics.terminatedExams}</div><div class="l">Terminated attempts</div></div>
      </div>
      <p class="small">A flag or warning records that a monitored event occurred — it does not by itself establish academic misconduct.</p>
    `);
    app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
    app.querySelectorAll('[data-flags]').forEach((b) => b.addEventListener('click', () => { location.hash = `#/lecturer/${b.dataset.flags}/flags`; }));
    app.querySelectorAll('[data-tl]').forEach((b) => b.addEventListener('click', () => { location.hash = `#/lecturer/${examId}/attempt/${b.dataset.tl}/timeline`; }));
  }

  await refresh();
  liveTimer = setInterval(refresh, 4000);
}

// ---------- Lecturer: flags (Section 9) ----------

async function viewFlags(examId) {
  renderShell('lecturer', `<div class="empty">Loading flags…</div>`);
  const flags = await api(`/exams/${examId}/flags`);
  renderShell('lecturer', h`
    <div class="row" style="justify-content:space-between;">
      <h1>Flags</h1>
      <button class="ghost" data-nav="#/lecturer/${examId}/live">Back to live monitoring</button>
    </div>
    <p>Flagged events for this examination. Use neutral judgement — a flag records a monitored event, not a finding.</p>
    <div class="panel">
      ${flags.length ? flags.map((f) => h`
        <div class="flag-item ${['Automatic termination'].includes(f.category) ? 'danger' : ''}">
          <div class="flag-bar"></div>
          <div style="flex:1;">
            <div class="flag-cat">${esc(f.category)}</div>
            <div class="flag-meta">${esc(f.student)} (${esc(f.matric)}) · ${fmtTime(f.timestamp)}</div>
          </div>
          <div><button class="ghost" data-tl="${f.attemptId}">View timeline</button></div>
        </div>
      `).join('') : `<div class="empty">No flagged events recorded.</div>`}
    </div>
  `);
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
  app.querySelectorAll('[data-tl]').forEach((b) => b.addEventListener('click', () => { location.hash = `#/lecturer/${examId}/attempt/${b.dataset.tl}/timeline`; }));
}

// ---------- Lecturer: attempt timeline (Section 10) ----------

async function viewTimeline(examId, attemptId) {
  renderShell('lecturer', `<div class="empty">Loading timeline…</div>`);
  const [timeline, { attempt }] = await Promise.all([api(`/attempts/${attemptId}/timeline`), api(`/attempts/${attemptId}`)]);
  renderShell('lecturer', h`
    <div class="row" style="justify-content:space-between;">
      <h1>Activity timeline</h1>
      <button class="ghost" data-nav="#/lecturer/${examId}/live">Back to live monitoring</button>
    </div>
    <p>${esc(attempt.student)} (${esc(attempt.matric)}) — ${attempt.warnings} warning(s) · status: ${attempt.status}</p>
    <div class="panel">
      <div class="timeline">
        ${timeline.map((e) => h`
          <div class="tl-item ${e.type === 'auto_termination' ? 'danger' : (e.type === 'warning_issued' ? 'warn' : '')}">
            <div class="tl-time">${fmtTime(e.timestamp)}</div>
            <div class="tl-label">${esc(e.label)}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `);
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
}

// ---------- Student: pick an exam ----------

async function viewStudentHome() {
  renderShell('student', `<div class="empty">Loading examinations…</div>`, 'narrow');
  const exams = await api('/exams');
  renderShell('student', h`
    <h1>Available examinations</h1>
    <div class="stack">
      ${exams.length ? exams.map((e) => h`
        <div class="panel row" style="justify-content:space-between;">
          <div><h3>${esc(e.title)}</h3><p class="small">${esc(e.course)} · ${e.durationMinutes} min · <span class="badge ${e.securityLevel}">${e.securityLevel}</span></p></div>
          <button data-go="${e.id}">Begin</button>
        </div>
      `).join('') : `<div class="panel empty">No examinations are available right now.</div>`}
    </div>
  `, 'narrow');
  app.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => { location.hash = `#/student/${b.dataset.go}`; }));
}

// ---------- Student: full proctored flow ----------

async function viewStudentExam(examId) {
  const exam = await api(`/exams/${examId}`);
  const s = {
    exam,
    stage: 'confirm', // confirm -> precheck -> declaration -> exam -> done
    student: state.currentUser.name, matric: state.currentUser.matric,
    attempt: null,
    fullscreenGranted: false, cameraStatus: 'pending', micStatus: 'pending',
    timerHandle: null,
  };
  renderConfirmIdentity(s);
}

// Identity comes straight from the signed-in account — never from a form
// the student fills in — so a student can't start an attempt "as" someone
// else. This screen just confirms it's the right account before proceeding.
function renderConfirmIdentity(s) {
  renderShell('student', h`
    <h1>${esc(s.exam.title)}</h1>
    <p>${esc(s.exam.course)} · ${s.exam.durationMinutes} minutes · <span class="badge ${s.exam.securityLevel}">${s.exam.securityLevel}</span></p>
    <div class="panel stack">
      <div>
        <div class="small">Signed in as</div>
        <h3>${esc(s.student)}</h3>
        <p class="small">${esc(s.matric)}</p>
      </div>
      <p class="hint">Not you? Log out and sign in with the correct student account before continuing.</p>
      <div class="row" style="justify-content:flex-end;">
        <button id="notMeBtn" class="ghost">Not me — log out</button>
        <button id="continueIdBtn">Continue</button>
      </div>
    </div>
  `, 'narrow');
  el('#notMeBtn').addEventListener('click', async () => {
    await api('/auth/logout', { method: 'POST' });
    state.currentUser = null;
    location.hash = '#/login';
  });
  el('#continueIdBtn').addEventListener('click', () => {
    if (s.exam.securityLevel === 'proctored') renderPrecheck(s);
    else renderDeclaration(s, false);
  });
}

// Section 14: explain before requesting camera/mic access.
function showPermissionExplainer(kind) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'overlay';
    const isCam = kind === 'camera';
    overlay.innerHTML = h`
      <div class="card">
        <div class="kicker">${isCam ? '📷' : '🎙️'}</div>
        <h3>${isCam ? 'Camera permission' : 'Microphone permission'}</h3>
        <p>This examination requests ${isCam ? 'camera' : 'microphone'} access to confirm the device is present and working.
        ${isCam ? 'No video is recorded or stored — only permission status is checked.' : 'No audio is recorded or stored — only permission status is checked.'}
        Access is checked now, before the exam starts, and is not used again once your attempt begins unless your institution has separately configured continuous monitoring.</p>
        <div class="row" style="justify-content:flex-end;">
          <button class="secondary" id="declineBtn">Not now</button>
          <button id="allowBtn">Continue</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    el('#declineBtn', overlay).addEventListener('click', () => { overlay.remove(); resolve(false); });
    el('#allowBtn', overlay).addEventListener('click', () => { overlay.remove(); resolve(true); });
  });
}

async function checkCamera() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    stream.getTracks().forEach((t) => t.stop()); // never keep the stream open
    return 'ok';
  } catch { return 'fail'; }
}
async function checkMic() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    stream.getTracks().forEach((t) => t.stop());
    return 'ok';
  } catch { return 'fail'; }
}

// Section 11: pre-exam security check.
async function renderPrecheck(s) {
  const items = [
    { key: 'camera', title: 'Camera permission', desc: 'Required for this proctored examination', needed: s.exam.controls.cameraPermission },
    { key: 'mic', title: 'Microphone permission', desc: 'Required for this proctored examination', needed: s.exam.controls.micPermission },
    { key: 'fullscreen', title: 'Fullscreen support', desc: 'Your browser must support fullscreen mode', needed: s.exam.controls.fullscreenRequired },
    { key: 'connection', title: 'Internet connection', desc: 'A stable connection is required to submit your answers', needed: true },
    { key: 'browser', title: 'Browser compatibility', desc: 'Modern Chrome, Firefox, Edge or Safari', needed: true },
    { key: 'session', title: 'Examination session', desc: 'Confirming your attempt with the server', needed: true },
  ].filter((i) => i.needed);

  const results = {};

  function draw() {
    const allChecked = items.every((i) => results[i.key] === 'ok');
    const anyFail = items.some((i) => results[i.key] === 'fail');
    renderShell('student', h`
      <h1>System check</h1>
      <p>These checks confirm your device can support this proctored examination's security requirements.</p>
      <div class="panel">
        ${items.map((i) => h`
          <div class="check-item">
            <div class="icon">${results[i.key] === 'ok' ? '✅' : results[i.key] === 'fail' ? '⚠️' : '⏳'}</div>
            <div class="body"><div class="title">${i.title}</div><div class="desc">${i.desc}</div></div>
            <div class="status ${results[i.key] === 'ok' ? 'ok' : results[i.key] === 'fail' ? 'fail' : 'pending'}">
              ${results[i.key] === 'ok' ? 'Passed' : results[i.key] === 'fail' ? 'Failed' : 'Checking…'}
            </div>
          </div>
        `).join('')}
      </div>
      ${anyFail ? `<p class="hint">One or more checks failed. Fix the item above (grant the permission, switch browser, or reconnect) and try again — you can't start the examination until all required checks pass.</p>` : ''}
      <div class="row" style="justify-content:flex-end;margin-top:16px;">
        ${anyFail ? `<button id="retryBtn" class="secondary">Retry checks</button>` : ''}
        <button id="continueBtn" ${allChecked ? '' : 'disabled'}>Continue</button>
      </div>
    `, 'narrow');
    if (el('#retryBtn')) el('#retryBtn').addEventListener('click', run);
    if (allChecked) el('#continueBtn').addEventListener('click', () => renderDeclaration(s, true));
  }

  async function run() {
    for (const i of items) results[i.key] = 'pending';
    draw();
    for (const i of items) {
      if (i.key === 'camera') { const r = await (async () => { await showPermissionExplainer('camera'); return checkCamera(); })(); results.camera = r; s.cameraStatus = r; }
      else if (i.key === 'mic') { const r = await (async () => { await showPermissionExplainer('microphone'); return checkMic(); })(); results.mic = r; s.micStatus = r; }
      else if (i.key === 'fullscreen') results.fullscreen = (document.documentElement.requestFullscreen ? 'ok' : 'fail');
      else if (i.key === 'connection') results.connection = navigator.onLine ? 'ok' : 'fail';
      else if (i.key === 'browser') results.browser = ('fetch' in window && 'addEventListener' in document) ? 'ok' : 'fail';
      else if (i.key === 'session') { try { await api(`/exams/${s.exam.id}`); results.session = 'ok'; } catch { results.session = 'fail'; } }
      draw();
    }
  }

  await run();
}

// Section 12: integrity declaration.
function renderDeclaration(s, precheckDone) {
  renderShell('student', h`
    <div class="panel">
      <h2>Academic integrity declaration</h2>
      <p style="font-style:italic;">"I confirm that I am completing this examination independently and will not use unauthorized materials or assistance."</p>
      <label class="row" style="align-items:flex-start;gap:10px;">
        <input type="checkbox" id="agreeBox" style="margin-top:4px;">
        <span>I agree to the academic integrity declaration.</span>
      </label>
      <div class="row" style="justify-content:flex-end;margin-top:18px;">
        <button id="startBtn" disabled>Grant permissions &amp; start exam</button>
      </div>
    </div>
  `, 'narrow');
  const box = el('#agreeBox'); const btn = el('#startBtn');
  box.addEventListener('change', () => { btn.disabled = !box.checked; });
  btn.addEventListener('click', async () => {
    btn.disabled = true; btn.textContent = 'Starting…';
    try {
      const res = await api('/attempts', { method: 'POST', body: JSON.stringify({
        examId: s.exam.id, integrityAccepted: box.checked,
      })});
      s.attempt = res.attempt;
      startExam(s);
    } catch (err) {
      btn.disabled = false; btn.textContent = 'Grant permissions & start exam';
      alert(err.body?.error || 'Could not start the examination.');
    }
  });
}

// ---------- Exam taking (Sections 4, 5, 6, 7, 10) ----------

async function startExam(s) {
  s.stage = 'exam';
  s.remainingSec = Math.max(0, Math.floor((new Date(s.attempt.startedAt).getTime() + s.exam.durationMinutes * 60000 - Date.now()) / 1000));
  s.answers = {};
  s.localCache = [];

  if (s.exam.controls.fullscreenRequired && document.documentElement.requestFullscreen) {
    try { await document.documentElement.requestFullscreen(); } catch { /* handled by fullscreenchange below as unavailable */ }
  }

  attachMonitors(s);
  renderExam(s);

  s.timerHandle = setInterval(() => {
    s.remainingSec -= 1;
    const timerEl = el('#timerVal');
    if (timerEl) timerEl.textContent = fmtClock(s.remainingSec);
    if (s.remainingSec <= 0) { clearInterval(s.timerHandle); handleExpiry(s); }
  }, 1000);
}

function attachMonitors(s) {
  const controls = s.exam.controls;

  document.addEventListener('fullscreenchange', s._fsHandler = async () => {
    if (s.stage !== 'exam') return;
    if (!document.fullscreenElement && controls.fullscreenRequired) {
      const r = await sendEvent(s, 'fullscreen_exit', { note: 'left fullscreen' });
      showFullscreenWarning(s, r);
    }
  });

  document.addEventListener('visibilitychange', s._visHandler = async () => {
    if (s.stage !== 'exam') return;
    if (document.hidden && controls.tabSwitchDetection) {
      const r = await sendEvent(s, 'tab_switch', { note: 'tab hidden' });
      handleEventResult(s, r, 'Suspicious activity detected.', 'You have left the examination window. Please return to the examination.');
    }
  });

  window.addEventListener('blur', s._blurHandler = async () => {
    if (s.stage !== 'exam' || !controls.focusLossDetection) return;
    await sendEvent(s, 'focus_loss', null);
  });
  window.addEventListener('focus', s._focusHandler = async () => {
    if (s.stage !== 'exam' || !controls.focusLossDetection) return;
    await sendEvent(s, 'focus_regain', null);
  });

  window.addEventListener('offline', s._offlineHandler = async () => {
    if (s.stage !== 'exam') return;
    showConnectionBanner(true);
    try { await sendEvent(s, 'connection_loss', null); } catch { /* expected while offline */ }
  });
  window.addEventListener('online', s._onlineHandler = async () => {
    if (s.stage !== 'exam') return;
    showConnectionBanner(false);
    await sendEvent(s, 'connection_recovery', null);
    flushLocalCache(s);
  });
}

function detachMonitors(s) {
  document.removeEventListener('fullscreenchange', s._fsHandler);
  document.removeEventListener('visibilitychange', s._visHandler);
  window.removeEventListener('blur', s._blurHandler);
  window.removeEventListener('focus', s._focusHandler);
  window.removeEventListener('offline', s._offlineHandler);
  window.removeEventListener('online', s._onlineHandler);
}

async function sendEvent(s, type, details) {
  const r = await api(`/attempts/${s.attempt.id}/event`, { method: 'POST', body: JSON.stringify({ type, details }) });
  if (r.attempt) s.attempt = r.attempt;
  return r;
}

function handleEventResult(s, r, title1, msg1) {
  if (r.terminated) return showTermination(s);
  if (r.warningIssued) showWarningOverlay(s, r.warningIssued);
}

function showWarningOverlay(s, count) {
  const limit = s.exam.warningLimit;
  const copy = {
    1: ['⚠️', 'Suspicious activity detected.', 'You have left the examination window. Please return to the examination.'],
    2: ['⚠️', 'Second violation detected.', 'Further violations may terminate your examination.'],
    3: ['🚨', 'Maximum warnings reached.', 'Your examination has been automatically terminated and submitted.'],
  }[Math.min(count, 3)];
  const overlay = document.createElement('div');
  overlay.className = 'overlay';
  overlay.innerHTML = h`
    <div class="card warning">
      <div class="kicker">${copy[0]}</div>
      <h3>${copy[1]}</h3>
      <p>${copy[2]}</p>
      <p class="small">Warning ${count} of ${limit ?? '∞'}</p>
      <div class="row" style="justify-content:flex-end;">
        <button id="ackBtn">Return to examination</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  el('#ackBtn', overlay).addEventListener('click', async () => {
    overlay.remove();
    if (s.exam.controls.fullscreenRequired && document.documentElement.requestFullscreen && !document.fullscreenElement) {
      try { await document.documentElement.requestFullscreen(); await sendEvent(s, 'fullscreen_restored', null); } catch {}
    }
  });
}

function showFullscreenWarning(s, r) {
  if (r.terminated) return showTermination(s);
  if (r.warningIssued) return showWarningOverlay(s, r.warningIssued);
}

function showConnectionBanner(lost) {
  let banner = el('#connBanner');
  if (lost) {
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'connBanner';
      banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#A23A2E;color:white;text-align:center;padding:8px;font-size:13px;z-index:60;';
      banner.textContent = '⚠️ Connection lost. Your answers are being saved locally and will sync automatically.';
      document.body.prepend(banner);
    }
  } else if (banner) banner.remove();
}

function flushLocalCache(s) {
  if (!s.localCache.length) return;
  const pending = s.localCache.splice(0, s.localCache.length);
  pending.forEach((item) => {
    api(`/attempts/${s.attempt.id}/answer`, { method: 'POST', body: JSON.stringify(item) }).catch(() => s.localCache.push(item));
  });
}

function renderExam(s) {
  renderShell('student', h`
    <div class="exam-shell">
      <div>
        <h1>${esc(s.exam.title)}</h1>
        <p class="small">${esc(s.exam.course)} · Attempt for ${esc(s.student)} (${esc(s.matric)})</p>
        <div class="panel" style="margin-top:16px;">
          ${s.exam.questions.map((q, i) => h`
            <div class="qcard">
              <div class="qno">Question ${i + 1}</div>
              <p>${esc(q.prompt)}</p>
              <textarea data-qid="${q.id}" placeholder="Type your answer…"></textarea>
            </div>
          `).join('')}
        </div>
      </div>
      <div class="exam-sidebar panel">
        <div class="small">Time remaining</div>
        <div class="timer" id="timerVal">${fmtClock(s.remainingSec)}</div>
        <div class="warn-count">Warnings: <span id="warnVal">${s.attempt.warnings}</span>/${s.exam.warningLimit ?? '∞'}</div>
        <div class="divider"></div>
        <div class="small">Security</div>
        <p class="small">${s.exam.controls.fullscreenRequired ? '🖥️ Fullscreen required' : ''}${s.exam.controls.tabSwitchDetection ? '<br>👁️ Tab monitoring on' : ''}${s.exam.controls.cameraPermission ? '<br>📷 Camera checked' : ''}</p>
        <div class="divider"></div>
        <button id="submitBtn" style="width:100%;">Submit examination</button>
      </div>
    </div>
  `);

  app.querySelectorAll('textarea[data-qid]').forEach((ta) => {
    ta.addEventListener('change', async () => {
      const item = { questionId: ta.dataset.qid, answer: ta.value };
      s.answers[item.questionId] = item.answer;
      if (!navigator.onLine) { s.localCache.push(item); return; }
      try {
        const r = await api(`/attempts/${s.attempt.id}/answer`, { method: 'POST', body: JSON.stringify(item) });
        s.attempt = r.attempt;
      } catch (err) {
        if (err.status === 410) return showExpired(s);
        s.localCache.push(item);
      }
    });
  });

  el('#submitBtn').addEventListener('click', async () => {
    if (!confirm('Submit your examination now? This cannot be undone.')) return;
    s.stage = 'done';
    clearInterval(s.timerHandle);
    detachMonitors(s);
    const r = await api(`/attempts/${s.attempt.id}/submit`, { method: 'POST' });
    s.attempt = r.attempt;
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    showCompletion(s);
  });
}

async function handleExpiry(s) {
  s.stage = 'done';
  detachMonitors(s);
  try {
    const r = await api(`/attempts/${s.attempt.id}/submit`, { method: 'POST' });
    s.attempt = r.attempt;
  } catch {}
  showExpired(s);
}

function showExpired(s) {
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  renderShell('student', h`
    <div class="overlay" style="position:static;background:none;padding:0;">
      <div class="card" style="margin:60px auto;">
        <h3>Examination closed</h3>
        <p>The examination period has ended. Your answers have been automatically submitted and recorded.</p>
        <button data-nav="#/student">Leave examination</button>
      </div>
    </div>
  `, 'narrow');
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
}

function showTermination(s) {
  s.stage = 'done';
  clearInterval(s.timerHandle);
  detachMonitors(s);
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  renderShell('student', h`
    <div class="card danger" style="margin:60px auto;max-width:440px;">
      <div class="kicker">🚨</div>
      <h3>Examination terminated</h3>
      <p>You received ${s.attempt.warnings} warnings for suspicious activity. Your examination has been automatically submitted.</p>
      <button data-nav="#/student">Leave examination</button>
    </div>
  `, 'narrow');
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
}

function showCompletion(s) {
  const answered = Object.keys(s.answers).length;
  const total = s.exam.questions.length;
  renderShell('student', h`
    <div class="panel" style="max-width:440px;margin:60px auto;">
      <h2>Exam completed</h2>
      <p>${esc(s.exam.course)}</p>
      <p class="small" style="color:var(--teal-deep);font-weight:500;">✓ Submitted successfully</p>
      <div class="divider"></div>
      <div class="stack" style="gap:8px;">
        <div class="row" style="justify-content:space-between;"><span class="small">Questions answered</span><span>${answered} / ${total}</span></div>
        <div class="row" style="justify-content:space-between;"><span class="small">Questions unanswered</span><span>${total - answered}</span></div>
        <div class="row" style="justify-content:space-between;"><span class="small">Score</span><span>${s.exam.immediateResults ? 'Pending grading' : 'Not released'}</span></div>
        <div class="row" style="justify-content:space-between;"><span class="small">Warnings</span><span>${s.attempt.warnings}</span></div>
      </div>
      <div class="divider"></div>
      <button data-nav="#/student" style="width:100%;">Done</button>
    </div>
  `, 'narrow');
  app.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => { location.hash = b.dataset.nav; }));
}
