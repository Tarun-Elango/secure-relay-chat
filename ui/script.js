// ─────────────────────────────────────────────
// CRYPTO UTILITIES (NaCl box — X25519 + XSalsa20-Poly1305)
// ─────────────────────────────────────────────
const { box, randomBytes } = nacl;
const { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } = nacl.util;

//used to generate a new key pair for the user when they connect
function generateKeyPair() {
  return box.keyPair();
}

// this function encrypts a plaintext message for a specific peer using their public key and the sender's secret key. It returns the ciphertext and nonce, both encoded in Base64 for easy transmission.
function encryptForPeer(message, theirPublicKeyB64, mySecretKey) {
  const theirPublicKey = decodeBase64(theirPublicKeyB64);
  const nonce = randomBytes(box.nonceLength);// one nonce for each message, generated randomly
  const msgBytes = new TextEncoder().encode(message);
  const encrypted = box(msgBytes, nonce, theirPublicKey, mySecretKey);
  return {
    ciphertext: encodeBase64(encrypted),
    nonce: encodeBase64(nonce),
  };
}

function decryptFromPeer(ciphertextB64, nonceB64, theirPublicKeyB64, mySecretKey) {
  try {
    const ciphertext = decodeBase64(ciphertextB64);
    const nonce = decodeBase64(nonceB64);
    const theirPublicKey = decodeBase64(theirPublicKeyB64);
    const decrypted = box.open(ciphertext, nonce, theirPublicKey, mySecretKey);
    if (!decrypted) return null;
    return new TextDecoder().decode(decrypted);
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
let ws = null;
let myKeyPair = null;
let myId = null;
let myNickname = '';
let myIsAdmin = false;
let peers = new Map(); // id -> { nickname, publicKey }
let lastErrorMessage = null; // store error for login screen display
let hasConnectedOnce = false; // track if we've successfully connected at least once

// ─────────────────────────────────────────────
// UI HELPERS
// ─────────────────────────────────────────────
function addMessage({ from, fromNickname, text, isOwn, isSystem, isInfo }) {
  // isOwn: message sent by us
  // isSystem: informational message about joins/leaves, not from a user
  // isInfo: a system message that's purely informational (like connection success), styled differently

  const messages = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = 'msg' + (isOwn ? ' own' : '') + (isSystem ? ' system' : '');

  if (!isSystem) {
    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    meta.textContent = isOwn ? 'you' : (fromNickname || from || 'unknown');
    div.appendChild(meta);
  }

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble' + (isInfo ? ' info' : '');
  bubble.textContent = text;
  div.appendChild(bubble);

  if (!isSystem) {
    const badge = document.createElement('div');
    badge.className = 'enc-badge';
    badge.textContent = 'e2e encrypted';
    div.appendChild(badge);
  }

  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

function updatePeerList() {
  const list = document.getElementById('peer-list');
  const count = document.getElementById('peer-count-num');
  count.textContent = peers.size;

  if (peers.size === 0) {
    list.innerHTML = '<div class="no-peers">Waiting for<br>others to join…</div>';
    return;
  }

  list.innerHTML = '';
  for (const [id, peer] of peers.entries()) {
    const item = document.createElement('div');
    item.className = 'peer-item';
    const adminBadge = peer.isAdmin ? '<span style="color: var(--system);">[ADMIN]</span>' : '';
    const fingerprint = peer.publicKey;
    item.innerHTML = `
      <div class="peer-avatar">${peer.nickname[0].toUpperCase()}</div>
      <div>
        <div class="peer-name">${escapeHtml(peer.nickname)} ${adminBadge}</div>
        <div class="peer-fingerprint" title="Verify this out-of-band">${fingerprint}</div>
      </div>
    `;
    list.appendChild(item);
  }


}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

function setConnectionStatus(connected) {
  const dot = document.getElementById('status-dot');
  const errorBar = document.getElementById('error-bar');
  const sendBtn = document.getElementById('send-btn');
  dot.className = 'status-dot' + (connected ? '' : ' offline');
  errorBar.style.display = connected ? 'none' : 'block';
  sendBtn.disabled = !connected;
}

// ─────────────────────────────────────────────
// WEBSOCKET + PROTOCOL
// ─────────────────────────────────────────────
function connectToServer(serverUrl, nickname, token) {
  if (ws) ws.close();

  console.log('Attempting to connect to:', serverUrl);
  ws = new WebSocket(serverUrl);

  ws.onopen = () => {
    console.log('WebSocket connected!');
    hasConnectedOnce = true;
    setConnectionStatus(true);
    ws.send(JSON.stringify({
      type: 'join',
      nickname,
      publicKey: encodeBase64(myKeyPair.publicKey),
      token: token
    }));
  };

  ws.onclose = () => {
    console.log('WebSocket closed');
    setConnectionStatus(false);
    if (hasConnectedOnce) {
      // If we've connected before, try to reconnect silently
      setTimeout(() => connectToServer(serverUrl, nickname, token), 3000);
    }
  };

  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
    setConnectionStatus(false);
    
    // If this is the first connection attempt, show error on login screen
    if (!hasConnectedOnce) {
      const errorDiv = document.getElementById('login-error');
      const errorMsg = 'Unable to connect to server. Please check the server URL and try again.';
      if (errorDiv) {
        errorDiv.style.display = 'block';
        errorDiv.textContent = `⚠ ${errorMsg}`;
      }
      // Go back to login screen
      document.getElementById('login-screen').style.display = 'flex';
      document.getElementById('chat-screen').style.display = 'none';
      ws.close();
    }
  };

  ws.onmessage = (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }
    handleServerMessage(msg);
  };
}

function handleServerMessage(msg) {
  switch (msg.type) {
    case 'error': {
      lastErrorMessage = msg.msg;
      const errorDiv = document.getElementById('login-error');
      if (errorDiv) {
        errorDiv.style.display = 'block';
        errorDiv.textContent = `⚠ ${msg.msg}`;
      }
      addMessage({ text: `⚠ ${msg.msg}`, isSystem: true, isInfo: true });
      // If they haven't gotten in yet, bounce back to login screen
      document.getElementById('login-screen').style.display = 'flex';
      document.getElementById('chat-screen').style.display = 'none';
      break;
    }
    case 'roster': { // this is sent by the server when we first connect, containing our assigned ID and the current list of connected clients
      myId = msg.yourId;
      myIsAdmin = msg.isAdmin; // store this globally
      peers.clear();
      for (const peer of msg.clients) {
        peers.set(peer.id, { nickname: peer.nickname, publicKey: peer.publicKey, isAdmin: peer.isAdmin });
      }
      updatePeerList();
      const roleText = myIsAdmin ? '👑 You are admin' : 'Connected';
      addMessage({ text: `Connected. Your ID generated by the server: ${myId.slice(0,8)}…`, isSystem: true, isInfo: true });
      break;
    }

    case 'peer_joined': {
      peers.set(msg.id, { nickname: msg.nickname, publicKey: msg.publicKey, isAdmin: msg.isAdmin });// format of peers map: key is client.id, value is an object with nickname and publicKey properties
      updatePeerList();
      addMessage({ text: `${msg.nickname} joined`, isSystem: true });
      break;
    }

    case 'peer_left': {
      peers.delete(msg.id);
      updatePeerList();
      addMessage({ text: `${msg.nickname} left`, isSystem: true });
      break;
    }

    case 'message': {
      if (msg.from === myId) return; // shouldn't happen but guard anyway

      const sender = peers.get(msg.from);
      if (!sender) return;

      const plaintext = decryptFromPeer(
        msg.ciphertext,
        msg.nonce,
        sender.publicKey,
        myKeyPair.secretKey
      );

      if (plaintext === null) {
        addMessage({ text: '[could not decrypt message]', isSystem: true });
        return;
      }

      addMessage({
        from: msg.from,
        fromNickname: msg.fromNickname || sender.nickname,
        text: plaintext,
      });
      break;
    }
  }
}

// ─────────────────────────────────────────────
// SEND A MESSAGE
// Encrypts separately for each peer (NaCl box)
// ─────────────────────────────────────────────
function sendMessage(text) {
  if (!text.trim() || !ws || ws.readyState !== WebSocket.OPEN) return;

  // For simplicity in PoC: encrypt once per peer and send individually
  // In production: use a shared group key or Signal's sender key
  for (const [peerId, peer] of peers.entries()) {
    const { ciphertext, nonce } = encryptForPeer(text, peer.publicKey, myKeyPair.secretKey);
    ws.send(JSON.stringify({
      type: 'message',
      to: peerId,
      ciphertext,
      nonce,
    }));
  }

  // Show our own message locally (we don't echo to ourselves from server)
  addMessage({ text, isOwn: true });
}

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const nicknameInput = document.getElementById('nickname-input');
  const serverInput = document.getElementById('server-input');
  const connectBtn = document.getElementById('connect-btn');
  const msgInput = document.getElementById('msg-input');
  const sendBtn = document.getElementById('send-btn');
  const tokenInput = document.getElementById('token-input');

  // Default server URL
  // serverInput.value = `ws://${location.hostname}:8080`;
  

  connectBtn.addEventListener('click', () => {
    const nickname = nicknameInput.value.trim();
    const serverUrl = serverInput.value.trim();
    const token = tokenInput.value.trim();
    if (!nickname) { nicknameInput.focus(); return; }
    if (!serverUrl) { serverInput.focus(); return; }
    if (!token) { tokenInput.focus(); return; }

    // Check for unencrypted connection on non-localhost
    if (serverUrl.startsWith('ws://') && location.hostname !== 'localhost') {
      const errorDiv = document.getElementById('login-error');
      if (errorDiv) {
        errorDiv.style.display = 'block';
        errorDiv.textContent = '⚠ Warning: Using unencrypted WebSocket (ws://) on a remote server. Consider using wss:// instead.';
      }
      return;
    }

    // Clear previous error
    const errorDiv = document.getElementById('login-error');
    if (errorDiv) errorDiv.style.display = 'none';

    // Reset connection flag for new attempt
    hasConnectedOnce = false;

    // Generate keypair
    myKeyPair = generateKeyPair();
    myNickname = nickname;

    // Show chat screen
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('chat-screen').style.display = 'flex';

    // Show truncated public key in header (like a fingerprint)
    const pubKeyHex = encodeBase64(myKeyPair.publicKey);
    document.getElementById('my-key-display').textContent = `Public key: ${pubKeyHex}`;

    connectToServer(serverUrl, nickname, token);
  });

  // Send on Enter (Shift+Enter for newline)
  msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const text = msgInput.value;
      if (text.trim()) {
        sendMessage(text);
        msgInput.value = '';
      }
    }
  });

  sendBtn.addEventListener('click', () => {
    const text = msgInput.value;
    if (text.trim()) {
      sendMessage(text);
      msgInput.value = '';
    }
  });

  // Enter in login fields
  [nicknameInput, serverInput].forEach(el => {
    // this allows the user to press Enter in either the nickname or server input to trigger the connect button
    el.addEventListener('keydown', e => {
      if (e.key === 'Enter') connectBtn.click();
    });
  });
});