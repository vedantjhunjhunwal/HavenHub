// HavenHub dashboard. Plain ES2020, no dependencies.
// Security notes: the token lives only in memory (never in storage or URLs); every value from the
// server is written with textContent, never innerHTML; the page runs under a CSP with no inline code.
'use strict';

const $ = (id) => document.getElementById(id);
const state = { token: null, homeId: null, stream: null, deadline: null };

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (res.status === 401 && state.token) signOut();
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

// ---- auth -------------------------------------------------------------------
async function signIn(event) {
  event.preventDefault();
  $('auth-error').textContent = '';
  try {
    const { token } = await api('POST', '/api/auth/login', { email: $('email').value, password: $('password').value });
    state.token = token;
    $('password').value = '';
    await start();
  } catch (e) {
    $('auth-error').textContent = e.message;
  }
}

async function register() {
  $('auth-error').textContent = '';
  try {
    await api('POST', '/api/auth/register', { email: $('email').value, password: $('password').value });
    await signIn(new Event('submit'));
  } catch (e) {
    $('auth-error').textContent = e.message;
  }
}

function signOut() {
  state.token = null;
  state.homeId = null;
  if (state.stream) state.stream.abort();
  $('app').hidden = true;
  $('auth').hidden = false;
  $('logout').hidden = true;
  $('whoami').textContent = '';
}

async function start() {
  const me = await api('GET', '/api/me');
  $('whoami').textContent = me.email;
  $('auth').hidden = true;
  $('app').hidden = false;
  $('logout').hidden = false;
  await loadHomes();
}

// ---- homes ------------------------------------------------------------------
async function loadHomes(selectId) {
  const homes = await api('GET', '/api/homes');
  const select = $('home-select');
  select.replaceChildren(...homes.map((h) => {
    const o = document.createElement('option');
    o.value = h.id;
    o.textContent = `${h.name} (${h.role})`;
    return o;
  }));
  if (homes.length === 0) return;
  select.value = selectId || homes[0].id;
  await openHome(Number(select.value));
}

async function createHome(event) {
  event.preventDefault();
  try {
    const home = await api('POST', '/api/homes', { name: $('home-name').value, panelPin: $('home-pin').value });
    $('home-pin').value = '';
    await loadHomes(home.id);
  } catch (e) {
    alertBox('panel-error', e);
  }
}

async function openHome(homeId) {
  state.homeId = homeId;
  await Promise.all([refreshPanel(), refreshDevices(), refreshEvents()]);
  listen(homeId);
}

// ---- security panel -----------------------------------------------------------
async function refreshPanel() {
  const s = await api('GET', `/api/homes/${state.homeId}/security`);
  const mode = $('mode');
  mode.textContent = s.mode.replace('Armed', 'Armed ');
  mode.className = 'badge' + (s.mode === 'Disarmed' ? '' : ' armed');
  const alarm = $('alarm');
  alarm.textContent = s.alarm === 'Idle' ? 'All quiet' : s.alarm.replace('Delay', ' delay');
  alarm.className = 'badge' + (s.alarm === 'Triggered' ? ' alarm' : s.alarm.endsWith('Delay') ? ' delay' : '');
  state.deadline = s.deadlineMs;
  $('open-sensors').textContent = s.openSensors.length ? `Open: ${s.openSensors.join(', ')}` : '';
  if (s.pinLocked) $('panel-error').textContent = 'Too many wrong PINs: disarming is locked for a few minutes.';
}

async function arm(mode) {
  $('panel-error').textContent = '';
  try {
    await api('POST', `/api/homes/${state.homeId}/security/arm`, { mode, bypass: false });
  } catch (e) {
    if (e.message.startsWith('open_sensors') && confirm(`${e.message}\nArm anyway and bypass them?`)) {
      await api('POST', `/api/homes/${state.homeId}/security/arm`, { mode, bypass: true }).catch((x) => alertBox('panel-error', x));
    } else {
      alertBox('panel-error', e);
    }
  }
  await refreshPanel();
}

async function disarm(event) {
  event.preventDefault();
  $('panel-error').textContent = '';
  try {
    await api('POST', `/api/homes/${state.homeId}/security/disarm`, { pin: $('pin').value });
  } catch (e) {
    alertBox('panel-error', e);
  }
  $('pin').value = '';
  await refreshPanel();
}

function tickCountdown() {
  const left = state.deadline ? Math.ceil((state.deadline - Date.now()) / 1000) : 0;
  $('countdown').textContent = left > 0 ? `${left} s left` : '';
}

// ---- devices ----------------------------------------------------------------
const ACTION_ARGS = {
  set_setpoint: () => ({ celsius: Number(prompt('Target temperature (7-32 °C)', '21')) }),
  set_mode: () => ({ mode: prompt('Mode: heat, cool, auto or off', 'heat') }),
  dim: () => ({ level: Number(prompt('Brightness (1-100)', '50')) }),
};

function describeState(s) {
  return Object.entries(s || {}).map(([k, v]) => `${k}: ${v}`).join(' · ');
}

async function refreshDevices() {
  const devices = await api('GET', `/api/homes/${state.homeId}/devices`);
  const tpl = $('device-template');
  $('devices').replaceChildren(...devices.map((d) => {
    const li = tpl.content.firstElementChild.cloneNode(true);
    li.dataset.id = d.id;
    li.querySelector('.name').textContent = d.name;
    li.querySelector('.kind').textContent = d.kind;
    li.querySelector('.state').textContent = describeState(d.state);
    li.querySelector('.online-dot').classList.toggle('on', d.online);
    li.querySelector('.online-dot').title = d.online ? 'Online' : 'Offline';
    const actions = li.querySelector('.actions');
    for (const action of d.actions) {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = action.replace('set_', '');
      b.addEventListener('click', () => command(d.id, action, b));
      actions.append(b);
    }
    return li;
  }));
}

async function command(deviceId, action, button) {
  $('device-error').textContent = '';
  const args = ACTION_ARGS[action] ? ACTION_ARGS[action]() : {};
  button.disabled = true;
  try {
    // One idempotency key per click: a retried request can never run the command twice.
    const c = await api('POST', `/api/homes/${state.homeId}/devices/${deviceId}/commands?wait=true`,
      { action, args, idempotencyKey: crypto.randomUUID() });
    if (c.status !== 'Acked') $('device-error').textContent = `${action}: ${c.status}${c.error ? ` (${c.error})` : ''}`;
  } catch (e) {
    alertBox('device-error', e);
  } finally {
    button.disabled = false;
  }
}

// ---- events -----------------------------------------------------------------
function eventItem(type, detail, at) {
  const li = document.createElement('li');
  const t = document.createElement('time');
  t.dateTime = new Date(at).toISOString();
  t.textContent = new Date(at).toLocaleTimeString();
  li.append(t, document.createTextNode(`${type.replace(/^(device|panel):/, '')} ${detail || ''}`));
  return li;
}

async function refreshEvents() {
  const page = await api('GET', `/api/homes/${state.homeId}/events?limit=50`);
  $('events').replaceChildren(...page.items.map((e) => eventItem(e.type, e.detail, e.at)));
}

// Live updates over Server-Sent Events, read with fetch so the token goes in a header, not the URL.
async function listen(homeId) {
  if (state.stream) state.stream.abort();
  const controller = new AbortController();
  state.stream = controller;
  try {
    const res = await fetch(`/api/homes/${homeId}/stream`, { headers: { Authorization: `Bearer ${state.token}` }, signal: controller.signal });
    $('live').classList.add('on');
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += value;
      let cut;
      while ((cut = buffer.indexOf('\n\n')) >= 0) {
        const block = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 2);
        const line = block.split('\n').find((l) => l.startsWith('data: '));
        if (line) onLiveEvent(JSON.parse(line.slice(6)));
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') console.warn('stream ended', e);
  } finally {
    $('live').classList.remove('on');
  }
}

function onLiveEvent(e) {
  const detail = e.data.event || (e.data.signals || []).join(', ') || e.data.status || '';
  $('events').prepend(eventItem(e.type, detail, e.at));
  if (e.type === 'panel') refreshPanel();
  if (e.type.startsWith('device')) refreshDevices();
}

function alertBox(id, e) {
  $(id).textContent = e.message || String(e);
}

// ---- wiring -----------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  $('auth-form').addEventListener('submit', signIn);
  $('register').addEventListener('click', register);
  $('logout').addEventListener('click', signOut);
  $('home-form').addEventListener('submit', createHome);
  $('home-select').addEventListener('change', (e) => openHome(Number(e.target.value)));
  $('disarm-form').addEventListener('submit', disarm);
  document.querySelectorAll('[data-arm]').forEach((b) => b.addEventListener('click', () => arm(b.dataset.arm)));
  setInterval(tickCountdown, 500);
});
