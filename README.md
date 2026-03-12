# Flutter iOS Burp Interceptor and TLS Bypass via Frida
> Intercept Flutter-based iOS application network traffic using Frida - **no OpenVPN, no iptables, no jailbreak tweak required.**

---

## 🔍 The Problem

Flutter apps are more difficult to intercept compared to standard iOS apps.

| Feature | Standard iOS App | Flutter App |
|---|---|---|
| Networking stack | iOS native (CFNetwork) | Bundled Dart VM |
| System proxy | Respected | **Ignored** |
| Certificate store | iOS system store | **BoringSSL (bundled)** |
| SSL pinning bypass | Standard tools work | Standard tools **fail** |

Flutter bundles its own TLS implementation (BoringSSL), its own socket layer, and completely bypasses iOS system networking which means tools like SSL Kill Switch, Proxyman, and Charles Proxy don't work out of the box.

---

## ⚙️ How It Works

The interception works at **two levels inside the Flutter binary itself**:

### 1. Traffic Redirection - `GetSockAddr` Hook
Flutter creates sockets through its Dart VM via an internal function called `Socket_CreateConnect`. Inside this function, destination IP and port are assembled in a `sockaddr` struct via `GetSockAddr`.

By hooking `GetSockAddr` and overwriting the IP/port bytes in memory **before the socket opens**, all connections are silently redirected to Burp Suite regardless of what host the app was trying to reach.

### 2. TLS Bypass - `verify_peer_cert` Replace
Flutter's TLS handshake calls `verify_peer_cert` (inside BoringSSL) to validate the server's certificate. Instead of trying to patch certificate validation byte-by-byte, the script **completely replaces** this function with one that always returns success, allowing Flutter to accept any certificate including Burp's self-signed one.

### 3. Finding Functions - Embedded String Scanning
Rather than unreliable byte pattern matching, the script finds the exact function addresses by scanning for **debug strings baked into the binary at compile time**:

- `"third_party/boringssl/src/ssl/handshake.cc"` → leads to `verify_peer_cert`
- `"Socket_CreateConnect"` → leads to `GetSockAddr`

This approach works reliably across Flutter versions because the source file paths are always present in the binary.

---

## 🏗️ Architecture

```
App makes HTTPS request
         ↓
Dart VM builds sockaddr struct
         ↓
[HOOK] GetSockAddr fires
  → IP overwritten  → 192.168.x.x (Burp machine)
  → Port overwritten → 8080
         ↓
Connection hits Burp Suite
         ↓
Burp presents self-signed certificate
         ↓
[HOOK] verify_peer_cert fires
  → Always returns success (0)
         ↓
TLS handshake completes
         ↓
✅ Full decrypted traffic visible in Burp
```

---

## 📋 Prerequisites

- Jailbroken iOS device
- [Frida](https://frida.re) installed on your machine (`pip install frida-tools`)
- `frida-server` running on the iOS device (matching version)
- Burp Suite (or any MITM proxy)

---

## 🚀 Setup

### 1. Install frida-server on iOS device

```bash
# On the iOS device via SSH
frida-server -l 0.0.0.0 &
```

### 2. Configure Burp Suite

```
Proxy → Options → Edit Listener:
  ✅ Bind to port: 8080
  ✅ Bind to address: All interfaces
  ✅ Support invisible proxying: ENABLED
  ✅ Redirect to host: (LEAVE EMPTY)
```

### 3. Edit the script

Open `flutter-ios-intercept.js` and set your machine's IP and Burp port:

```javascript
var BURP_PROXY_IP = "192.168.1.x";   // Your machine IP
var BURP_PROXY_PORT = 8080;           // Your Burp port
```

### 4. Run

```bash
frida -l flutter-ios-intercept.js -f com.your.app.bundle -H <device_ip>
```

---

## 📄 Script Overview

```
flutter-ios-intercept.js
├── parseMachO()              — Parses Flutter binary headers to locate sections
├── scanMemory()              — Scans for embedded strings to find function addresses
│   ├── "handshake.cc"        → locates verify_peer_cert
│   └── "Socket_CreateConnect"→ locates GetSockAddr
├── hook("GetSockAddr")       — Redirects traffic to proxy
└── hook("verifyPeerCert")    — Bypasses TLS certificate validation
```

---

## ✅ Expected Output

```
[*] Flutter loaded!
[*] Flutter base: 0x...
[*] handshake string found at: 0x...
[*] Socket_CreateConnect string found at: 0x...
[*] Socket_CreateConnect func @ 0x...
[*] GetSockAddr @ 0x...
[*] Hooking GetSockAddr...
[*] Hooking verifyPeerCert...
[*] Redirecting → 192.168.1.x:8080
[*] verify_peer_cert bypassed
```

---

## ❓ Why Not Standard Approaches?

| Approach | Why It Fails on Flutter |
|---|---|
| Wi-Fi system proxy | Flutter's Dart VM ignores system proxy settings |
| SSL Kill Switch | Patches iOS Security.framework - Flutter uses BoringSSL |
| Objection SSL bypass | Same issue - targets iOS/Android native TLS |
| Hook `connect()` syscall | Flutter uses Network.framework's NWConnection, not BSD sockets |
| Hook `nw_endpoint_create_host` | Port is 0 at this stage, set elsewhere |
| Byte pattern TLS bypass | Too many false positives, crashes the app |

---

## 📚 Credits

Core script logic by [hackcatml/frida-flutterproxy](https://github.com/hackcatml/frida-flutterproxy).

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Only use it against applications you own or have explicit written permission to test. Unauthorized interception of network traffic is illegal.
