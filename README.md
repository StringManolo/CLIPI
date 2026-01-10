# CLIPI - CLI Proxy Interceptor

A lightweight HTTP/HTTPS proxy interceptor for security testing and debugging, inspired by Burp Suite but designed for the command line.

## Features

- HTTP/HTTPS traffic interception with full decryption
- Manual request forwarding/blocking
- Request modification with your editor
- Request history tracking
- Verbose mode with full headers/bodies
- Beautiful colored terminal output
- Automatic CA certificate generation
- On-the-fly certificate generation per domain

## Installation

```bash
git clone https://github.com/StringManolo/clipi
cd clipi
npm i
chmod +x clipi.js
```

### Dependencies

CLIPI requires `node-forge` for HTTPS certificate generation:

```bash
npm install node-forge simpleargumentsparser
```

Your `package.json` should include:

```json
{
  "name": "clipi",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "node-forge": "^1.3.1",
    "simpleargumentsparser": "^2.1.1"
  }
}
```

## Usage

```bash
./clipi.js

./clipi.js -i

./clipi.js -p 9090 -v

./clipi.js -H 0.0.0.0 -i -v
```

### Options

- `-h, --help` - Show help message
- `-H, --host` - Proxy host (default: 127.0.0.1)
- `-p, --port` - Proxy port (default: 8080)
- `-i, --intercept` - Enable manual intercept mode
- `-v, --verbose` - Show detailed headers and bodies

## Cromite Setup

### Installing Cromite

Download from the official repository:

```
https://github.com/uazo/cromite/releases
```

Download the latest `.apk` file for your architecture (arm64-v8a recommended) and install.

### Configuring Proxy in Cromite

1. Start CLIPI:
   ```bash
   ./clipi.js -i
   ```

2. Open Cromite:
   - Settings → Privacy and security → Proxy Configuration
   - Check the box "Use a single proxy list for all schemes (PAC format)"
   - Enter: `PROXY 127.0.0.1:8080`
   - Scroll down and press Apply

3. Navigate to any site and watch the intercepted requests

## Test Sites

- **Google Gruyere** - https://google-gruyere.appspot.com/
- **alert(1) to win** - https://alf.nu/alert1
- **XSS Game** - https://xss-game.appspot.com/
- **Juice Shop** - https://juice-shop.herokuapp.com/
- **PortSwigger Academy** - https://portswigger.net/web-security

## Testing

```bash
./clipi.js -i -v
```

In Cromite, visit http://neverssl.com and watch the intercepted request.

## Intercept Mode

When running with `-i` flag:

- **[f]orward** - Send the request
- **[d]rop** - Block the request
- **[m]odify** - Modify request with your editor (vim/nano/etc.)

### Editor Configuration

CLIPI uses your system's default editor. Set it with:

```bash
export EDITOR=vim
export EDITOR=nano
export EDITOR=code --wait
```

### Modify Example

```bash
╔═══ REQUEST INTERCEPTED ═══╗
Method: POST
URL: example.com/api/login
Headers:
  content-type: application/json
Body:
{"username":"admin","password":"test"}
╚═══════════════════════════╝

[f]orward, [d]rop, [m]odify: m
```

Selecting `m` opens your editor with the full HTTP request. Modify any part (method, path, headers, body) and save. CLIPI will send the modified request.

## HTTPS Interception

CLIPI automatically generates a Certificate Authority (CA) on first run and creates certificates on-the-fly for each HTTPS domain.

### Certificate Location

CA certificate is stored at: `~/.clipi/certs/ca-cert.pem`

### Installing CA Certificate on Android

1. **Start CLIPI** (this generates the CA):
   ```bash
   ./clipi.js
   ```

2. **Transfer the certificate to your device:**
   ```bash
   adb push ~/.clipi/certs/ca-cert.pem /sdcard/Download/
   ```

   Or transfer via USB/cloud storage.

3. **Install on Android:**
   - Settings → Security → Encryption & credentials
   - Install a certificate → CA certificate
   - Select `ca-cert.pem` from Downloads
   - Name it "CLIPI CA" and confirm

4. **Verify installation:**
   - Settings → Security → Trusted credentials → User
   - You should see "CLIPI CA"

### Testing HTTPS Interception

```bash
./clipi.js -i -v
```

In Cromite, visit https://example.com and you'll see the decrypted request in CLIPI.

### Security Notes

- The CA private key is stored locally at `~/.clipi/certs/ca-key.pem`
- Keep this file secure - anyone with it can intercept your HTTPS traffic
- Remove the CA from your device when done testing
- Only use on devices you own and control

## Security Warning

For educational and authorized testing only. Do not use on systems without permission.
