// Snapvault dashboard client. Plain fetch against the JSON API.
/* global document, fetch */

const $ = (sel) => document.querySelector(sel);

const loginView = $('#login-view');
const dashView = $('#dash-view');
const logoutBtn = $('#logout');
const whoami = $('#whoami');

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

function showDashboard(user) {
  loginView.hidden = true;
  dashView.hidden = false;
  logoutBtn.hidden = false;
  whoami.textContent = `${user.displayName} (@${user.username})`;
  loadSnapshots();
  loadActivity();
}

function showLogin() {
  loginView.hidden = false;
  dashView.hidden = true;
  logoutBtn.hidden = true;
  whoami.textContent = '';
}

async function loadSnapshots() {
  const { ok, body } = await api('/api/snapshots');
  if (!ok) return;
  const list = $('#snap-rows');
  list.innerHTML = '';
  for (const s of body.snapshots ?? []) {
    const li = document.createElement('li');
    li.className = 'snap';
    li.innerHTML = `
      <div class="snap__main">
        <span class="snap__title">${s.title}</span>
        <span class="badge badge--${s.visibility}">${s.visibility}</span>
      </div>
      <code class="snap__handle">${s.handle}</code>`;
    list.appendChild(li);
  }
}

async function loadActivity() {
  const { ok, body } = await api('/api/activity');
  if (!ok) return;
  const list = $('#activity-rows');
  list.innerHTML = '';
  for (const a of body.activity ?? []) {
    const li = document.createElement('li');
    li.className = 'feeditem';
    li.innerHTML = `
      <span class="feeditem__who">${a.owner}</span>
      <span class="feeditem__title">shared “${a.title}”</span>
      <code class="feeditem__handle">${a.handle}</code>`;
    list.appendChild(li);
  }
}

// Login
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const err = $('#login-error');
  err.hidden = true;
  const { ok, body } = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({
      username: form.username.value,
      password: form.password.value,
    }),
  });
  if (ok) {
    showDashboard(body.user);
  } else {
    err.textContent = body.error ?? 'Login failed';
    err.hidden = false;
  }
});

// Logout
logoutBtn.addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' });
  showLogin();
});

// View a snapshot by handle.
$('#view-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const handle = $('#view-handle').value.trim();
  const out = $('#view-out');
  const { ok, body } = await api(`/api/snapshots/${encodeURIComponent(handle)}`);
  out.hidden = false;
  out.textContent = ok ? JSON.stringify(body.snapshot, null, 2) : `Error: ${body.error ?? ''}`;
});

// Edit a snapshot by handle — the client surface of the write path.
$('#edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const handle = $('#edit-handle').value.trim();
  const out = $('#edit-out');
  const payload = {};
  const shared = $('#edit-shared').value.trim();
  const title = $('#edit-title').value.trim();
  if (shared) payload.sharedWith = shared;
  if (title) payload.title = title;
  const { ok, body } = await api(`/api/snapshots/${encodeURIComponent(handle)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
  out.hidden = false;
  out.textContent = ok ? JSON.stringify(body.snapshot, null, 2) : `Error: ${body.error ?? ''}`;
  if (ok) loadSnapshots();
});

// On load, check whether we already have a session.
(async () => {
  const { ok, body } = await api('/api/me');
  if (ok && body.user) showDashboard(body.user);
  else showLogin();
})();
