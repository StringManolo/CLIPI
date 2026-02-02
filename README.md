![CLIPI](repo_assets/CLIPI_transparent.png)

A lightweight HTTP/HTTPS proxy interceptor for security testing and debugging, inspired by Burp Suite but designed for the command line.

## Features
- HTTP/HTTPS traffic interception with automated full en/decryption (MITM)
- **Request and Response interception** - Intercept and modify both requests and responses
- **Rules/Middleware System** - Automate modifications with persistent rules
- **Script Injection** - Inject JavaScript into HTML responses with automatic CSP bypass
- **Header Manipulation** - Add, modify, or remove headers automatically
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
./clipi.js -ir             # Intercept requests AND responses
./clipi.js -p 9090 -ivd    # Custom port with intercept, verbose, and debug
./clipi.js -H 0.0.0.0 -ivl # Listen on all interfaces with logging
./clipi.js repeater        # Open Repeater tool (tabs persist)
./clipi.js rules           # Open Rules Manager (create automation rules)
```

### Options
- `-h, --help` - Show help message
- `-H, --host` - Proxy host (default: 127.0.0.1)
- `-p, --port` - Proxy port (default: 8080)
- `-i, --intercept` - Enable manual request intercept mode
- `-r, --iresponse` - Enable manual response intercept mode
- `-v, --verbose` - Show detailed headers and bodies
- `-d, --debug` - Show debug information (SSL, decompression, etc.)
- `-l, --log` - Log all requests/responses to `requests.log`
- `repeater` - Open the Repeater tool with saved tabs
- `rules` - Open the Rules Manager for automation
- `--version` - Show version number

## Rules & Middleware System

CLIPI includes a powerful rules system for automating request/response modifications. Rules are persistent and apply automatically to matching traffic.

### Accessing Rules Manager
```bash
./clipi.js rules
```

Or press `Ctrl+S` while the proxy is running.

### Rule Types
- **Modify** - Change requests/responses on-the-fly
- **Block** - Drop matching traffic
- **Redirect** - Redirect to different URLs

### Match Conditions
Rules can match based on:
- **URL patterns** (regex)
- **HTTP methods** (GET, POST, etc.)
- **Headers** (regex matching)
- **Body content** (regex)
- **Status codes** (for responses)

### Actions
- **Script Injection** - Inject JavaScript into HTML responses (inline or external)
- **Find & Replace** - Regex-based text replacement in body
- **Header Manipulation** - Add, modify, or remove headers
- **CSP Bypass** - Automatically remove Content-Security-Policy headers
- **Scope Control** - Apply to requests, responses, or both

### Quick Script Injection

The fastest way to inject a script and bypass CSP:

```bash
# 1. Start proxy
./clipi.js

# 2. Open Rules Manager (in another terminal or press Ctrl+S)
./clipi.js rules

# 3. Select: ⚡ Quick: Script Injection + CSP Bypass

# 4. Configure:
#    - Rule name: My Development Script
#    - Script type: External script (from URL)
#    - Script URL: http://localhost:3000/customScript.js
#    - Match URL: (leave empty for all HTML)

# Done! The rule will:
# ✓ Detect HTML responses (Content-Type: text/html)
# ✓ Inject your script into <body>
# ✓ Remove CSP headers that block script execution
```

### CSP Headers Removed Automatically
When using script injection, these headers are removed:
- `Content-Security-Policy`
- `Content-Security-Policy-Report-Only`
- `X-Content-Security-Policy`
- `X-WebKit-CSP`

### Rule Examples

**Inject Analytics Script:**
```json
{
  "name": "Inject Analytics",
  "scope": "response",
  "matchHeaders": { "content-type": "text/html" },
  "action": {
    "injectScript": { "src": "http://localhost:3000/analytics.js" },
    "removeHeaders": ["content-security-policy"]
  }
}
```

**Block Tracking:**
```json
{
  "name": "Block Analytics",
  "type": "block",
  "scope": "request",
  "matchUrl": "analytics\\.google\\.com"
}
```

**Modify API Response:**
```json
{
  "name": "Bypass Role Check",
  "scope": "response",
  "matchUrl": "/api/users",
  "action": {
    "body": {
      "search": "\"role\":\"user\"",
      "replace": "\"role\":\"admin\""
    }
  }
}
```

**Add CORS Headers:**
```json
{
  "name": "Permissive CORS",
  "scope": "response",
  "matchUrl": "api\\.example\\.com",
  "action": {
    "headers": {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
    }
  }
}
```

**Remove Frame Protection:**
```json
{
  "name": "Allow Iframe Embedding",
  "scope": "response",
  "action": {
    "removeHeaders": ["x-frame-options", "frame-options"]
  }
}
```

### Rules Storage
Rules are saved to: `~/.clipi/rules.json`

You can:
- ✅ Enable/disable rules without deleting them
- ✅ View detailed rule configuration
- ✅ Create multiple rules that apply simultaneously
- ✅ Edit the JSON file directly for advanced configurations

### Rules Workflow
```bash
# 1. Create rule via Quick Script Injection
./clipi.js rules
> Select: ⚡ Quick: Script Injection + CSP Bypass
> Enter: http://localhost:3000/debug.js

# 2. Start proxy (rule applies automatically)
./clipi.js -v

# 3. Browse any website - script injected automatically
# 4. View logs to see modifications
tail -f requests.log

# 5. Toggle rules on/off as needed
./clipi.js rules
> Select: 🔄 Toggle Rule
```

## Response Interception

Intercept and modify server responses before they reach the client.

### Enable Response Interception
```bash
./clipi.js -r              # Response intercept only
./clipi.js -ir             # Both request AND response intercept
```

### Response Intercept Actions
When a response is intercepted:
- **→ Forward** - Send response as-is to the client
- **✎ Modify** - Edit response (status, headers, body) in your editor
- **✗ Drop** - Block the response

### Modify Response Example
```bash
╔═══ RESPONSE INTERCEPTED ═══╗
║ Status: 200 OK
║ Content-Type: text/html
╚═════════════════════════════╝

? Choose action: (Use arrow keys)
❯ → Forward - Send response as-is
  ✎ Modify  - Edit response in editor
  ✗ Drop    - Block this response
```

Selecting **✎ Modify** opens your editor with:
```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1234

<!DOCTYPE html>
<html>
...
```

You can modify:
- Status code and message
- Response headers
- Response body

### Combined Request + Response Interception
```bash
./clipi.js -ir

# Intercept request:
# - Modify authentication token
# - Forward to server

# Intercept response:
# - Change status from 403 to 200
# - Inject debugging script
# - Forward to browser
```

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

When running with `-r` flag (response intercept):
- **→ Forward** - Send the response
- **✎ Modify** - Modify response with your editor
- **✗ Drop** - Block the response

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
- All rules applications logged

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

### Full debugging session with response interception
```bash
./clipi.js -H 0.0.0.0 -p 9090 -irdvl
```
- Listen on all interfaces
- Port 9090
- Request AND response intercept
- Verbose output
- Debug mode
- Logging enabled

### Script injection for development
```bash
# 1. Create injection rule
./clipi.js rules
> ⚡ Quick: Script Injection + CSP Bypass
> http://localhost:3000/devtools.js

# 2. Start proxy (script injected automatically)
./clipi.js -v

# 3. Browse any site - your script runs on every HTML page
```

### API response modification
```bash
# 1. Create modification rule
./clipi.js rules
> + Add Rule
> Modify → Find & Replace
> Search: "premium":false
> Replace: "premium":true

# 2. Start proxy
./clipi.js

# 3. API responses modified automatically
```

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

### Keyboard Shortcuts
- `Ctrl+R` - Open Repeater (while proxy is running)
- `Ctrl+S` - Open Rules Manager (while proxy is running)
- `Ctrl+C` - Stop proxy and show history

## Tests

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
(02:44:40:3646) /root/2026/CLIPI
> npm run test

> clipi@1.1.0 test
> vitest


 DEV  v4.0.16 /root/2026/CLIPI

 ✓ tests/integration/clipi.test.js (34 tests) 341ms
   ✓ CLIPI E2E (34)
     ✓ Should bind auto to 127.0.0.1:8080 12ms
     ✓ Should start in passive intercept mode 1ms
     ✓ Should get example.com HTTP request in pasive mode 1ms
     ✓ Should get 200 HTTP status code from example.com request in pasive mode 2ms
     ✓ Should get example.com server headers from CURL output 2ms
     ✓ Should get example.com HTML body from CURL output 1ms
     ✓ Should get example.com HTTPS CONNECT request in pasive mode 5ms
     ✓ Should get example.com HTTPS request in pasive mode 1ms
     ✓ Should get 200 HTTP status code from example.com request in Secure pasive mode 7ms
     ✓ Should get https://example.com HTML body from CURL output 2ms
     ✓ Should bind to 127.0.0.2:8080 with --host 127.0.0.2 flag 1ms
     ✓ Should get example.com HTML body from CURL output with --host 127.0.0.2 flag 1ms
     ✓ Should bind to 127.0.0.1:8081 with --port 8081 flag 2ms
     ✓ Should get example.com HTML body from CURL output with --port 8081 flag 2ms
     ✓ Should detect --log flag as ENABLED 2ms
     ✓ Should create file requests.log 5ms
     ✓ Should log session start 2ms
     ✓ Should log headers 3ms
     ✓ Should log example.com request headers 1ms
     ✓ Should log example.com response headers 2ms
     ✓ Should log example.com HTTPS response body 2ms
     ✓ Should detect --intercept flag as ACTIVE 1ms
     ✓ Should show Forward option 1ms
     ✓ Should Forward https://example.com response request body to CURL 3ms
     ✓ Should show Drop option 1ms
     ✓ Should show drop message confirmation 1ms
     ✓ Should show Request blocked by proxy response 1ms
     ✓ Should show modify option 1ms
     ✓ Should detect request modified 1ms
     ✓ Should get response after closing editor without changes 1ms
     ✓ Should show modify option 1ms
     ✓ Should detect request modified 1ms
     ✓ Should get 405 Method Not Allowed from CLIPI 1ms
     ✓ Should get 405 Method Not Allowed from curl -v 2ms

 Test Files  1 passed (1)
      Tests  34 passed (34)
   Start at  02:44:47
   Duration  47.12s (transform 271ms, setup 0ms, import 45.00s, tests 341ms, environment 1ms)
```

## Use Cases

### Web Application Penetration Testing
- Intercept and modify authentication tokens
- Test for authorization bypasses
- Inject XSS payloads into forms
- Modify API responses to test client-side validation

### Development & Debugging
- Inject debugging scripts into production sites (local testing)
- Remove CSP to test external libraries
- Modify API responses to test error handling
- Add CORS headers for local development

### Security Research
- Analyze encrypted HTTPS traffic
- Compare request/response variations
- Test WAF bypasses with request modification
- Export requests as cURL for documentation

### Mobile App Testing
- Intercept mobile app API calls
- Modify JSON responses on-the-fly
- Test app behavior with different server responses
- Export API calls for reverse engineering

## Security Warning
**For educational and authorized testing only. Do not use on systems without permission.**

The tool intercepts and decrypts HTTPS traffic. Use only in controlled environments for security research, penetration testing with proper authorization, or debugging your own applications.
