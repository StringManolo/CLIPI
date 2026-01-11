![CLIPI](repo_assets/CLIPI_transparent.png)

A lightweight HTTP/HTTPS proxy interceptor for security testing and debugging, inspired by Burp Suite but designed for the command line.

## Features
- HTTP/HTTPS traffic interception with automated full en/decryption (MITM)
- Repeater tool with multiple tabs
- Request/response comparison and search functionality
- Debug mode for detailed troubleshooting
- Complete request/response logging to file
- Copy requests as cURL commands
- Response history tracking
- Follow redirects toggle
- Manual request forwarding/blocking
- Request modification with your terminal text editor
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
./clipi.js                 # Basic proxy on port 8080
./clipi.js -iv             # Intercept mode with verbose output
./clipi.js -p 9090 -ivd    # Custom port with intercept, verbose, and debug
./clipi.js -H 0.0.0.0 -ivl # Listen on all interfaces with logging
./clipi.js repeater        # Open Repeater tool (tabs persist)
```

### Options
- `-h, --help` - Show help message
- `-H, --host` - Proxy host (default: 127.0.0.1)
- `-p, --port` - Proxy port (default: 8080)
- `-i, --intercept` - Enable manual intercept mode
- `-v, --verbose` - Show detailed headers and bodies
- `-d, --debug` - Show debug information (SSL, decompression, etc.)
- `-l, --log` - Log all requests/responses to `requests.log`
- `repeater` - Open the Repeater tool with saved tabs
- `--version` - Show version number

## Repeater Tool
CLIPI includes a full-featured Repeater with multiple tabs, similar to Burp Suite's Repeater.

### Accessing Repeater
Two ways to access Repeater:
1. **From proxy**: While proxy is running, press `Ctrl+R` (`^R`)
2. **Direct command**: `./clipi.js repeater`

### Repeater Features
- **Multiple tabs**: All tabs persist in `~/.clipi/repeater-tabs.json`
- **Send requests**: Resend modified requests with one click
- **Follow redirects**: Toggle automatic redirect following per tab
- **Response comparison**: Compare any two responses side-by-side
- **Search**: Search within response bodies
- **History**: View all previous responses for a request
- **cURL export**: Copy request as cURL command or save to file
- **Save/Load**: Save requests to file and load them later
- **Response headers**: View detailed response headers
- **Edit requests**: Modify any part of the request

### Repeater Workflow
1. Start proxy with intercept mode: `./clipi.js -i`
2. Intercept a request and select "🔄 Repeater"
3. Press `Ctrl+R` to open Repeater
4. Modify the request and send it multiple times
5. Compare responses, search for content, export as cURL

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
- **🔄 Repeater** - Send to Repeater tool for further testing
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
  🔄 Repeater - Send to Repeater
  ✗ Drop    - Block this request
```
Selecting **✎ Modify** opens your editor with the full HTTP request. Modify any part (method, path, headers, body) and save. CLIPI will send the modified request.

## Debug Mode
Use `-d` flag for detailed debugging information:
- Shows raw buffer sizes and compression details
- Displays decompression steps and errors
- Shows exact request/response timings
- Useful for troubleshooting SSL or encoding issues

Example: `./clipi.js -id`

## Logging
Use `-l` flag to log all traffic to `requests.log`:
- Complete request/response headers and bodies
- Timestamps for each entry
- Session separation with headers
- All repeater actions logged

Logs are saved to `requests.log` in the current directory.

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

## Advanced Examples

### Full debugging session
```bash
./clipi.js -H 0.0.0.0 -p 9090 -ivdl
```
- Listen on all interfaces
- Port 9090
- Intercept mode enabled
- Verbose output
- Debug mode
- Logging enabled

### Create repeater tabs for testing
```bash
./clipi.js -i
# Intercept requests and send them to Repeater
# Later, open Repeater separately:
./clipi.js repeater
```

### Export as cURL
From Repeater, select "📋 Copy as cURL" to:
1. View the exact cURL command
2. Save it as an executable script (with 775 permissions)

### Tests
I made the tests in a very "unique" way. This is because the test are expected to also be ran in low specs Android devices. 

##### Test Drawbacks
- Non isolated.
- Required to ran in a specific order
- Can be just a bit more difficult to debug than usual.
- You have to wait for all tests to ran to see how many passed / failed.

##### Test Advantages
- Test are shorter, both to write and to read, reusing code for multiple tests.
- Tests run much faster than usual because they are reusing a single process for multiple test instead of starting an independent node process for each test case.

##### Test results
```bash
(03:41:46:3097) /root/2026/CLIPI
> npm test

> clipi@1.1.0 test
> vitest


 DEV  v4.0.16 /root/2026/CLIPI

 ✓ tests/integration/clipi.test.js (24 tests) 227ms
   ✓ CLIPI E2E (24)
     ✓ Should bind auto to 127.0.0.1:8080 13ms
     ✓ Should start in passive intercept mode 1ms
     ✓ Should get example.com HTTP request in pasive mode 1ms
     ✓ Should get 200 HTTP status code from example.com request in pasive mode 2ms
     ✓ Should get example.com server headers from CURL output 2ms
     ✓ Should get example.com HTML body from CURL output 1ms
     ✓ Should get example.com HTTPS CONNECT request in pasive mode 1ms
     ✓ Should get example.com HTTPS request in pasive mode 1ms
     ✓ Should get 200 HTTP status code from example.com request in Secure pasive mode 2ms
     ✓ Should get https://example.com HTML body from CURL output 1ms
     ✓ Should bind to 127.0.0.2:8080 with --host 127.0.0.2 flag 1ms
     ✓ Should get example.com HTML body from CURL output with --host 127.0.0.2 flag 1ms
     ✓ Should bind to 127.0.0.1:8081 with --port 8081 flag 2ms
     ✓ Should get example.com HTML body from CURL output with --port 8081 flag 1ms
     ✓ Should detect --log flag as ENABLED 2ms
     ✓ Should create file requests.log 4ms
     ✓ Should log session start 1ms
     ✓ Should log headers 1ms
     ✓ Should log example.com request headers 1ms
     ✓ Should log example.com response headers 2ms
     ✓ Should log example.com HTTPS response body 1ms
     ✓ Should detect --intercept flag as ACTIVE 4ms
     ✓ Should show Forward option 2ms
     ✓ Should Forward https://example.com response request body to CURL 1ms

 Test Files  1 passed (1)
      Tests  24 passed (24)
   Start at  03:41:51
   Duration  23.30s (transform 228ms, setup 0ms, import 21.19s, tests 227ms, environment 1ms)
```

## Security Warning
**For educational and authorized testing only. Do not use on systems without permission.**

The tool intercepts and decrypts HTTPS traffic. Use only in controlled environments for security research, penetration testing with proper authorization, or debugging your own applications.
