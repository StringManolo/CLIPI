![CLIPI](repo_assets/CLIPI_transparent.png)
A lightweight HTTP/HTTPS proxy interceptor for security testing and debugging, inspired by Burp Suite but designed for the command line.                                        
## Features
- HTTP/HTTPS traffic interception with automated full en/decryption (MITM)
- Manual request forwarding/blocking                                                    - Request modification with your terminal text editor
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
## Usage
```bash
./clipi.js -iv
./clipi.js -p 9090 -iv
./clipi.js -H 0.0.0.0 -iv
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
   ./clipi.js -iv
   ```
2. Open Cromite:
   - Settings → Privacy and security → Proxy Configuration
   - Check the box "Use a single proxy list for all schemes (PAC format)"
   - Enter: `PROXY 127.0.0.1:8080`
   - Scroll down and press Apply
3. Navigate to any HTTP site and watch the intercepted requests
## Test Sites
- **Google Gruyere** - https://google-gruyere.appspot.com/
- **alert(1) to win** - https://alf.nu/alert1
- **XSS Game** - https://xss-game.appspot.com/
- **Juice Shop** - https://juice-shop.herokuapp.com/
- **PortSwigger Academy** - https://portswigger.net/web-security
## Intercept Mode
When running with `-i` flag, use **arrow keys ↑↓** to select an option and press **Enter**:
- **→ Forward** - Send the request
- **✎ Modify** - Modify request with your editor (vim/nano/etc.)
- **✗ Drop** - Block the request
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
║ Method: POST
║ URL: example.com/api/login
╚═══════════════════════════╝

? Choose action: (Use arrow keys)
❯ → Forward - Send request as-is
  ✎ Modify  - Edit request in editor
  ✗ Drop    - Block this request
```
Selecting **✎ Modify** opens your editor with the full HTTP request. Modify any part (method, path, headers, body) and save. CLIPI will send the modified request.
## HTTPS Interception
CLIPI automatically generates a Certificate Authority (CA) on first run and creates certificates on-the-fly for each HTTPS domain.
### Certificate Location
CA certificate is stored at: `~/.clipi/certs/ca-cert.pem`
### Installing CA Certificate on Android
1. **Start CLIPI** (this generates the CA):
   ```bash
   ./clipi.js -vi
   ```
2. **Transfer the certificate to your device:**
   ```bash
    cp ~/.clipi/certs/ca-cert.pem /storage/downloads/
   ```
3. **Install on Android:**
   - Settings → Security → Encryption & credentials
   - Install a certificate → CA certificate
   - Select `ca-cert.pem` from Downloads
   - Name it "CLIPI CA" and confirm
### Testing HTTPS Interception
```bash
./clipi.js -iv
```
In Cromite, visit https://example.com and you'll see the decrypted request in CLIPI.
### Security Notes
- The CA private key is stored locally at `~/.clipi/certs/ca-key.pem`
- Keep this file secure - anyone with it can intercept your HTTPS traffic
- Only use on devices you own and control

## Security Warning
For educational and authorized testing only. Do not use on systems without permission.
