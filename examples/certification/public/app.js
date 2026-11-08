/* global document, window, fetch */
const landing = document.getElementById('landing');
const account = document.getElementById('account');
const errorBox = document.getElementById('error');
const loginButton = document.getElementById('login');
const logoutButton = document.getElementById('logout');

function badge(text, tone = 'neutral') {
  const element = document.createElement('span');
  element.className = `badge ${tone}`;
  element.textContent = text;
  return element;
}

function initials(name, email) {
  const source = (name || email || '?').trim();
  const parts = source.split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
}

function renderAvatar(user) {
  const avatar = document.getElementById('avatar');
  avatar.replaceChildren();
  if (typeof user.picture === 'string' && user.picture.length > 0) {
    const image = document.createElement('img');
    image.src = user.picture;
    image.alt = '';
    image.referrerPolicy = 'no-referrer';
    image.addEventListener('error', () => {
      avatar.replaceChildren();
      avatar.textContent = initials(user.name, user.email);
    });
    avatar.append(image);
    return;
  }
  avatar.textContent = initials(user.name, user.email);
}

function renderBadges(user) {
  const badges = document.getElementById('user-badges');
  badges.replaceChildren();
  if (user.emailVerified === true) {
    badges.append(badge('E-mail vérifié', 'success'));
  }
  for (const role of user.roles ?? []) {
    badges.append(badge(role));
  }
  if (user.plan) badges.append(badge(user.plan, 'accent'));
}

function formatDate(value) {
  if (!value) return '—';
  // The SDK exposes Unix seconds; tolerate an ISO string or milliseconds too.
  const date =
    typeof value === 'number'
      ? new Date(value < 1e12 ? value * 1000 : value)
      : new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function showLanding() {
  landing.hidden = false;
  account.hidden = true;
  errorBox.hidden = true;
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function renderAccount(payload) {
  const user = payload.user ?? {};
  document.getElementById('account-title').textContent = user.name || user.email || 'Utilisateur CIRCLE';
  document.getElementById('user-email').textContent = user.email || 'Adresse e-mail non disponible';
  document.getElementById('user-sub').textContent = user.sub || '—';
  document.getElementById('user-plan').textContent = user.plan || '—';
  document.getElementById('user-roles').textContent =
    Array.isArray(user.roles) && user.roles.length > 0 ? user.roles.join(', ') : '—';
  document.getElementById('user-expiry').textContent = formatDate(payload.expiresAt);
  renderAvatar(user);
  renderBadges(user);
  landing.hidden = true;
  account.hidden = false;
  errorBox.hidden = true;
}

async function loadSession() {
  try {
    const response = await fetch('/auth/me', {
      headers: { accept: 'application/json' },
      cache: 'no-store',
    });
    if (response.status === 401) {
      showLanding();
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderAccount(await response.json());
  } catch {
    showLanding();
    showError('La session ne peut pas être chargée pour le moment.');
  }
}

async function logout() {
  logoutButton.disabled = true;
  try {
    const response = await fetch('/auth/logout', {
      method: 'POST',
      headers: { accept: 'application/json' },
      cache: 'no-store',
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    window.location.assign(typeof payload.logoutUrl === 'string' ? payload.logoutUrl : '/');
  } catch {
    logoutButton.disabled = false;
    showError('La déconnexion a échoué. Réessayez.');
  }
}

loginButton.addEventListener('click', () => window.location.assign('/auth/login'));
logoutButton.addEventListener('click', logout);

let refreshTimer;
function scheduleRefresh() {
  window.clearInterval(refreshTimer);
  refreshTimer = window.setInterval(() => {
    if (document.visibilityState === 'visible' && !account.hidden) void loadSession();
  }, 20000);
}

void loadSession();
scheduleRefresh();
