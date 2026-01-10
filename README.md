# CLIPI - CLI Proxy Interceptor

A lightweight HTTP/HTTPS proxy interceptor for security testing and debugging, inspired by Burp Suite but designed for the command line.

## Features

- HTTP/HTTPS traffic interception
- Manual request forwarding/blocking
- Request history tracking
- Verbose mode with full headers/bodies
- Beautiful colored terminal output

## Installation

```bash
git clone https://github.com/StringManolo/clipi
cd clipi
npm i
chmod +x clipi.js
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
- **[m]odify** - Modify request (coming soon)

```bash
╔═══ REQUEST INTERCEPTED ═══╗
Method: POST
URL: example.com/api/login
Headers:
  content-type: application/json
Body:
{"username":"admin","password":"test"}
╚═══════════════════════════╝

[f]orward, [d]rop, [m]odify: f
```

## HTTPS Notes

CLIPI creates transparent HTTPS tunnels but does NOT decrypt traffic (by design). You'll see CONNECT requests but not encrypted payloads.

## Security Warning

For educational and authorized testing only. Do not use on systems without permission.
