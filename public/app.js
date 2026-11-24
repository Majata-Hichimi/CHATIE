/**
 * public/app.js
 * Vanilla JS frontend for the Secure Chatroom API.
 *
 * Security measures in this file:
 *  - Uses ONLY textContent / createTextNode for all user & server data (never innerHTML)
 *  - No inline event handlers or inline scripts (strict CSP compatible)
 *  - No localStorage / sessionStorage / JS cookies (relies on server httpOnly session cookie)
 *  - Clears password fields after every login/register attempt
 *  - Never logs passwords or message contents to console
 *  - Disables buttons while requests are in flight to prevent double submits
 */

'use strict';

const PAGE_SIZE = 20;
const REFRESH_INTERVAL_MS = 5000;

// In-memory state only (never persisted to localStorage or sessionStorage)
let authMode = 'login'; // 'login' | 'register'
let currentUser = null;
let messages = [];
let hasMoreMessages = false;
let editingMessageId = null;
let confirmDeleteId = null;
let refreshTimerId = null;
let isAuthSubmitting = false;
let isSendingMessage = false;
let isMutatingMessage = false;

// DOM references
const loadingView = document.getElementById('loading-view');
const authView = document.getElementById('auth-view');
const chatView = document.getElementById('chat-view');

const tabLogin = document.getElementById('tab-login');
const tabRegister = document.getElementById('tab-register');
const authAlert = document.getElementById('auth-alert');
const authForm = document.getElementById('auth-form');
const authUsername = document.getElementById('auth-username');
const authPassword = document.getElementById('auth-password');
const authSubmit = document.getElementById('auth-submit');

const currentUsernameEl = document.getElementById('current-username');
const logoutBtn = document.getElementById('logout-btn');
const chatAlert = document.getElementById('chat-alert');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const charCounter = document.getElementById('char-counter');
const sendBtn = document.getElementById('send-btn');
const messagesEmpty = document.getElementById('messages-empty');
const messagesList = document.getElementById('messages-list');
const loadMoreBtn = document.getElementById('load-more-btn');

// --- Safe UI helpers ---
function showAlert(el, message, type) {
  el.textContent = message;
  el.className = `alert alert-${type}`;
  el.hidden = false;
}

function hideAlert(el) {
  el.textContent = '';
  el.hidden = true;
}

function setAuthMode(mode) {
  authMode = mode;
  const isLogin = mode === 'login';

  tabLogin.classList.toggle('active', isLogin);
  tabRegister.classList.toggle('active', !isLogin);
  tabLogin.setAttribute('aria-selected', String(isLogin));
  tabRegister.setAttribute('aria-selected', String(!isLogin));

  authPassword.setAttribute('autocomplete', isLogin ? 'current-password' : 'new-password');
  authSubmit.textContent = isLogin ? 'Login' : 'Create account';
  hideAlert(authAlert);
}

function stopAutoRefresh() {
  if (refreshTimerId !== null) {
    clearInterval(refreshTimerId);
    refreshTimerId = null;
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimerId = setInterval(() => {
    // Pause background re-render while user is editing or confirming delete
    if (editingMessageId === null && confirmDeleteId === null && !isMutatingMessage) {
      refreshLoadedMessages();
    }
  }, REFRESH_INTERVAL_MS);
}

function showAuthView(noticeMessage, noticeType = 'info') {
  stopAutoRefresh();
  currentUser = null;
  messages = [];
  hasMoreMessages = false;
  editingMessageId = null;
  confirmDeleteId = null;
  messagesList.textContent = '';

  loadingView.hidden = true;
  chatView.hidden = true;
  authView.hidden = false;

  if (noticeMessage) {
    showAlert(authAlert, noticeMessage, noticeType);
  } else {
    hideAlert(authAlert);
  }
}

function showChatView() {
  loadingView.hidden = true;
  authView.hidden = true;
  chatView.hidden = false;
  hideAlert(chatAlert);

  currentUsernameEl.textContent = currentUser.username;
  updateComposerState();
  startAutoRefresh();
}

function updateComposerState() {
  const len = messageInput.value.length;
  const hasNonWhitespace = messageInput.value.trim().length > 0;
  charCounter.textContent = `${len} / 500`;
  sendBtn.disabled = isSendingMessage || !hasNonWhitespace || len > 500;
}

function formatTimestamp(rawDate) {
  if (!rawDate) return '';
  const d = new Date(rawDate);
  if (Number.isNaN(d.getTime())) return String(rawDate);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// --- API client wrapper (same-origin session cookie, never exposes raw errors) ---
async function apiFetch(url, options = {}) {
  const fetchOptions = {
    method: options.method || 'GET',
    credentials: 'same-origin',
    headers: {},
  };

  if (options.body !== undefined) {
    fetchOptions.headers['Content-Type'] = 'application/json';
    fetchOptions.body = JSON.stringify(options.body);
  }

  let res;
  try {
    res = await fetch(url, fetchOptions);
  } catch (_networkErr) {
    return { ok: false, status: 0, data: null };
  }

  let data = null;
  try {
    data = await res.json();
  } catch (_parseErr) {
    data = null;
  }

  return { ok: res.ok, status: res.status, data };
}

function handleExpiredSession() {
  showAuthView('Your session has expired. Please log in again.', 'info');
}

function getFriendlyError(status, data) {
  if (status === 400 && data && typeof data.error === 'string') {
    return data.error;
  }
  if (status === 403) {
    return 'You are not allowed to perform that action.';
  }
  if (status === 404) {
    return 'That message no longer exists.';
  }
  if (status === 409 && data && typeof data.error === 'string') {
    return data.error;
  }
  if (status === 423 && data && typeof data.error === 'string') {
    return data.error;
  }
  if (status === 401 && data && typeof data.error === 'string') {
    return data.error;
  }
  return 'Something went wrong, please try again.';
}

// --- Message rendering (strictly textContent / createTextNode, zero innerHTML) ---
function renderMessages() {
  messagesList.textContent = '';
  messagesEmpty.hidden = messages.length > 0;
  loadMoreBtn.hidden = !hasMoreMessages;

  const fragment = document.createDocumentFragment();

  for (const msg of messages) {
    const isOwner = currentUser && msg.user_id === currentUser.id;
    const isEdited =
      msg.updated_at &&
      msg.created_at &&
      new Date(msg.updated_at).getTime() !== new Date(msg.created_at).getTime();

    const li = document.createElement('li');
    li.className = isOwner ? 'message-item own' : 'message-item';

    const meta = document.createElement('div');
    meta.className = 'message-meta';

    const authorWrap = document.createElement('div');
    authorWrap.className = 'message-author-wrap';

    const author = document.createElement('span');
    author.className = 'message-author';
    author.textContent = msg.username;
    authorWrap.appendChild(author);

    if (isOwner) {
      const youBadge = document.createElement('span');
      youBadge.className = 'badge badge-you';
      youBadge.textContent = 'You';
      authorWrap.appendChild(youBadge);
    }

    if (isEdited) {
      const editedBadge = document.createElement('span');
      editedBadge.className = 'badge';
      editedBadge.textContent = 'edited';
      authorWrap.appendChild(editedBadge);
    }

    const timeEl = document.createElement('span');
    timeEl.className = 'message-time';
    timeEl.textContent = formatTimestamp(msg.created_at);

    meta.appendChild(authorWrap);
    meta.appendChild(timeEl);
    li.appendChild(meta);

    if (isOwner && editingMessageId === msg.id) {
      li.appendChild(buildInlineEditForm(msg));
    } else {
      const bodyP = document.createElement('p');
      bodyP.className = 'message-content';
      bodyP.textContent = msg.content;
      li.appendChild(bodyP);

      if (isOwner) {
        li.appendChild(buildOwnerActions(msg));
      }
    }

    fragment.appendChild(li);
  }

  messagesList.appendChild(fragment);
}

function buildOwnerActions(msg) {
  const actions = document.createElement('div');
  actions.className = 'message-actions';

  if (confirmDeleteId === msg.id) {
    const promptSpan = document.createElement('span');
    promptSpan.className = 'muted';
    promptSpan.textContent = 'Delete this message?';

    const confirmBtn = document.createElement('button');
    confirmBtn.type = 'button';
    confirmBtn.className = 'btn btn-danger btn-sm';
    confirmBtn.textContent = 'Confirm';
    confirmBtn.disabled = isMutatingMessage;
    confirmBtn.addEventListener('click', () => handleDeleteMessage(msg.id));

    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.className = 'btn btn-secondary btn-sm';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.disabled = isMutatingMessage;
    cancelBtn.addEventListener('click', () => {
      confirmDeleteId = null;
      renderMessages();
    });

    actions.appendChild(promptSpan);
    actions.appendChild(confirmBtn);
    actions.appendChild(cancelBtn);
    return actions;
  }

  const editBtn = document.createElement('button');
  editBtn.type = 'button';
  editBtn.className = 'btn btn-secondary btn-sm';
  editBtn.textContent = 'Edit';
  editBtn.disabled = isMutatingMessage;
  editBtn.addEventListener('click', () => {
    editingMessageId = msg.id;
    confirmDeleteId = null;
    renderMessages();
  });

  const deleteBtn = document.createElement('button');
  deleteBtn.type = 'button';
  deleteBtn.className = 'btn btn-secondary btn-sm';
  deleteBtn.textContent = 'Delete';
  deleteBtn.disabled = isMutatingMessage;
  deleteBtn.addEventListener('click', () => {
    confirmDeleteId = msg.id;
    editingMessageId = null;
    renderMessages();
  });

  actions.appendChild(editBtn);
  actions.appendChild(deleteBtn);
  return actions;
}

function buildInlineEditForm(msg) {
  const form = document.createElement('form');
  form.className = 'inline-edit-form';

  const textarea = document.createElement('textarea');
  textarea.rows = 3;
  textarea.maxLength = 500;
  textarea.value = msg.content;
  textarea.setAttribute('aria-label', 'Edit message content');

  const bar = document.createElement('div');
  bar.className = 'inline-edit-bar';

  const counter = document.createElement('span');
  counter.className = 'muted';
  counter.textContent = `${textarea.value.length} / 500`;

  const btnGroup = document.createElement('div');
  btnGroup.className = 'message-actions';

  const saveBtn = document.createElement('button');
  saveBtn.type = 'submit';
  saveBtn.className = 'btn btn-primary btn-sm';
  saveBtn.textContent = 'Save';

  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button';
  cancelBtn.className = 'btn btn-secondary btn-sm';
  cancelBtn.textContent = 'Cancel';

  const syncEditBtn = () => {
    const len = textarea.value.length;
    counter.textContent = `${len} / 500`;
    saveBtn.disabled = isMutatingMessage || textarea.value.trim().length === 0 || len > 500;
  };
  syncEditBtn();

  textarea.addEventListener('input', syncEditBtn);
  cancelBtn.addEventListener('click', () => {
    editingMessageId = null;
    renderMessages();
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (isMutatingMessage) return;
    await handleEditMessage(msg.id, textarea.value, saveBtn, cancelBtn);
  });

  btnGroup.appendChild(saveBtn);
  btnGroup.appendChild(cancelBtn);
  bar.appendChild(counter);
  bar.appendChild(btnGroup);
  form.appendChild(textarea);
  form.appendChild(bar);
  return form;
}

// --- Data operations ---
async function restoreSession() {
  const res = await apiFetch('/api/me');
  if (res.status === 200 && res.data && res.data.user) {
    currentUser = res.data.user;
    showChatView();
    await loadInitialMessages();
    return;
  }

  if (res.status === 401) {
    showAuthView();
    return;
  }

  showAuthView('Something went wrong, please try again.', 'error');
}

async function loadInitialMessages() {
  const res = await apiFetch(`/api/messages?limit=${PAGE_SIZE}&offset=0`);
  if (res.status === 401) {
    handleExpiredSession();
    return;
  }
  if (!res.ok || !res.data) {
    showAlert(chatAlert, getFriendlyError(res.status, res.data), 'error');
    return;
  }

  messages = res.data.messages || [];
  hasMoreMessages = messages.length === PAGE_SIZE;
  renderMessages();
}

async function refreshLoadedMessages() {
  const targetCount = Math.max(messages.length, PAGE_SIZE);
  const collected = [];
  const seenIds = new Set();
  let offset = 0;
  let lastPageFull = false;

  while (offset < targetCount) {
    const batchLimit = Math.min(50, targetCount - offset);
    const res = await apiFetch(`/api/messages?limit=${batchLimit}&offset=${offset}`);
    if (res.status === 401) {
      handleExpiredSession();
      return;
    }
    if (!res.ok || !res.data) {
      // Do not overwrite chat UI on background network hiccup; alert only if severe
      return;
    }

    const batch = res.data.messages || [];
    for (const item of batch) {
      if (!seenIds.has(item.id)) {
        seenIds.add(item.id);
        collected.push(item);
      }
    }

    lastPageFull = batch.length === batchLimit;
    if (!lastPageFull) break;
    offset += batch.length;
  }

  messages = collected;
  hasMoreMessages = lastPageFull;
  renderMessages();
}

async function loadMoreMessages() {
  loadMoreBtn.disabled = true;
  try {
    const res = await apiFetch(`/api/messages?limit=${PAGE_SIZE}&offset=${messages.length}`);
    if (res.status === 401) {
      handleExpiredSession();
      return;
    }
    if (!res.ok || !res.data) {
      showAlert(chatAlert, getFriendlyError(res.status, res.data), 'error');
      return;
    }

    const batch = res.data.messages || [];
    const seen = new Set(messages.map((m) => m.id));
    for (const item of batch) {
      if (!seen.has(item.id)) {
        messages.push(item);
      }
    }
    hasMoreMessages = batch.length === PAGE_SIZE;
    renderMessages();
  } finally {
    loadMoreBtn.disabled = false;
  }
}

async function handleEditMessage(id, content, saveBtn, cancelBtn) {
  isMutatingMessage = true;
  saveBtn.disabled = true;
  cancelBtn.disabled = true;
  hideAlert(chatAlert);

  try {
    const res = await apiFetch(`/api/messages/${id}`, {
      method: 'PUT',
      body: { content },
    });

    if (res.status === 401) {
      handleExpiredSession();
      return;
    }
    if (res.status === 404) {
      editingMessageId = null;
      showAlert(chatAlert, 'That message no longer exists.', 'info');
      await refreshLoadedMessages();
      return;
    }
    if (!res.ok) {
      showAlert(chatAlert, getFriendlyError(res.status, res.data), 'error');
      return;
    }

    editingMessageId = null;
    await refreshLoadedMessages();
  } finally {
    isMutatingMessage = false;
    if (editingMessageId !== null) {
      saveBtn.disabled = false;
      cancelBtn.disabled = false;
    }
  }
}

async function handleDeleteMessage(id) {
  isMutatingMessage = true;
  hideAlert(chatAlert);
  renderMessages();

  try {
    const res = await apiFetch(`/api/messages/${id}`, {
      method: 'DELETE',
    });

    if (res.status === 401) {
      handleExpiredSession();
      return;
    }
    if (res.status === 404) {
      confirmDeleteId = null;
      showAlert(chatAlert, 'That message no longer exists.', 'info');
      await refreshLoadedMessages();
      return;
    }
    if (!res.ok) {
      confirmDeleteId = null;
      showAlert(chatAlert, getFriendlyError(res.status, res.data), 'error');
      renderMessages();
      return;
    }

    confirmDeleteId = null;
    await refreshLoadedMessages();
  } finally {
    isMutatingMessage = false;
  }
}

// --- Event listeners ---
tabLogin.addEventListener('click', () => setAuthMode('login'));
tabRegister.addEventListener('click', () => setAuthMode('register'));

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (isAuthSubmitting) return;

  const username = authUsername.value.trim();
  const password = authPassword.value;

  isAuthSubmitting = true;
  authSubmit.disabled = true;
  hideAlert(authAlert);

  try {
    const endpoint = authMode === 'login' ? '/api/login' : '/api/register';
    const res = await apiFetch(endpoint, {
      method: 'POST',
      body: { username, password },
    });

    if (authMode === 'register') {
      if (res.status === 201) {
        setAuthMode('login');
        authUsername.value = username;
        showAlert(authAlert, 'Account created successfully. Please log in.', 'success');
        authPassword.focus();
      } else {
        showAlert(authAlert, getFriendlyError(res.status, res.data), 'error');
      }
      return;
    }

    if (res.status === 200 && res.data && res.data.user) {
      currentUser = res.data.user;
      authUsername.value = '';
      showChatView();
      await loadInitialMessages();
    } else {
      showAlert(authAlert, getFriendlyError(res.status, res.data), 'error');
    }
  } finally {
    // Always clear the password input after every login/register attempt
    authPassword.value = '';
    isAuthSubmitting = false;
    authSubmit.disabled = false;
  }
});

logoutBtn.addEventListener('click', async () => {
  logoutBtn.disabled = true;
  try {
    await apiFetch('/api/logout', { method: 'POST' });
    showAuthView('You have been logged out.', 'info');
  } finally {
    logoutBtn.disabled = false;
  }
});

messageInput.addEventListener('input', updateComposerState);

messageForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (isSendingMessage) return;

  const content = messageInput.value;
  if (content.trim().length === 0 || content.length > 500) {
    updateComposerState();
    return;
  }

  isSendingMessage = true;
  updateComposerState();
  hideAlert(chatAlert);

  try {
    const res = await apiFetch('/api/messages', {
      method: 'POST',
      body: { content },
    });

    if (res.status === 401) {
      handleExpiredSession();
      return;
    }
    if (!res.ok) {
      showAlert(chatAlert, getFriendlyError(res.status, res.data), 'error');
      return;
    }

    messageInput.value = '';
    await refreshLoadedMessages();
  } finally {
    isSendingMessage = false;
    updateComposerState();
  }
});

loadMoreBtn.addEventListener('click', loadMoreMessages);

document.addEventListener('DOMContentLoaded', () => {
  setAuthMode('login');
  restoreSession();
});
