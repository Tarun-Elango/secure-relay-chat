# End-to-end encrypted group chat

A minimal, self-hosted, end-to-end encrypted group chat.

## How it works (security model)

```
Alice's browser                 Server (relay)              Bob's browser
──────────────                  ──────────────              ─────────────
generate keypair                                            generate keypair
send pubkey ──────────────────► store pubkey ────────────► receive Alice's pubkey

type "hello"
encrypt with Bob's pubkey
  → ciphertext ─────────────► relay blob ─────────────────► decrypt with own privkey
                               (sees only                     → "hello"
                                ciphertext)
```

- Encryption: **NaCl box** (X25519 key exchange + XSalsa20-Poly1305 AEAD)
- Library: **TweetNaCl.js** (audited, ~7KB, zero dependencies)
- The server is a **dumb relay** — it routes encrypted blobs and never sees plaintext
- Keys are generated fresh in the browser on each session — nothing is stored server-side

---

## Quick start (local)

### 1. Install and run the server

```bash
npm install
node server.js
# → SecureChat relay running on ws://localhost:8080
```

### 2. Serve the client

```bash
# Any static server works, e.g.:
npx serve .
# or:
python3 -m http.server 3000
```

### 3. Open in browser

Open `http://localhost:3000` (or wherever your static server is).

Open it in **multiple tabs or different browsers** to simulate multiple users.

---

## Test on your LAN

1. Find your local IP: `ip addr` or `ifconfig` → e.g. `192.168.1.42`
2. Run the server as above on that machine
3. Other devices on your network open: `http://192.168.1.42:3000`
4. Set the server URL to `ws://192.168.1.42:8080`

---

## Expose to the internet (for testing)

Use [ngrok](https://ngrok.com) — free tier works fine for PoC:

```bash
# Terminal 1: run the WebSocket server
node server.js

# Terminal 2: expose it
ngrok tcp 8080
# → Forwarding tcp://0.tcp.ngrok.io:XXXXX -> localhost:8080

# Terminal 3: serve the client
npx serve .
ngrok http 3000
# → Forwarding https://xxxx.ngrok.io -> localhost:3000
```

Share the `https://xxxx.ngrok.io` URL with others.
They set the server to `ws://0.tcp.ngrok.io:XXXXX`.

---

## Files

```
server.js      WebSocket relay server (~90 lines, Node.js)
index.html     Full client — crypto + UI in one file, no build step
package.json   Just one dependency: ws
README.md      This file
```

---

## Known PoC limitations (what to build next)

| Gap | Production solution |
|-----|-------------------|
| Keys reset on refresh | Store keypair in IndexedDB |
| No message history | Append-only encrypted log on server |
| Group encryption is N copies | Signal's Sender Keys protocol |
| No user auth | Password-based or invite tokens |
| No TLS on WebSocket | Use `wss://` with a cert (Let's Encrypt + Caddy) |
| No forward secrecy | Double Ratchet (Signal protocol) |

---

## Path to production

1. **Add TLS**: Put Caddy or Nginx in front, use `wss://` instead of `ws://`
2. **Add auth**: Simple invite-token system (server generates tokens, clients must present one)
3. **Persist keys**: IndexedDB so identity survives refresh
4. **Upgrade to Matrix/Synapse**: Once PoC validates the idea, migrate to a full protocol

---

## Dependencies

- **Server**: `ws` npm package only
- **Client**: `tweetnacl` + `tweetnacl-util` (loaded from cdnjs, or self-host them)
- No accounts, no cloud, no telemetry