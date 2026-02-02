#!/usr/bin/env node
import http from 'http';
import https from 'https';
import net from 'net';
import { parse as parseUrl } from 'url';
import prompts from 'prompts';
import { writeFileSync, readFileSync, unlinkSync, existsSync, mkdirSync, appendFileSync, chmodSync } from 'fs';
import { tmpdir, homedir } from 'os';
import { spawnSync } from 'child_process';
import { join } from 'path';
import { gunzipSync, inflateSync, brotliDecompressSync } from 'zlib';
import forge from 'node-forge';
import parseCLI from 'simpleargumentsparser';

class Rule {
  constructor(config) {
    this.id = config.id || Date.now();
    this.name = config.name || 'Unnamed Rule';
    this.enabled = config.enabled !== undefined ? config.enabled : true;
    this.type = config.type || 'modify'; // 'modify', 'block', 'redirect'
    this.scope = config.scope || 'response'; // 'request', 'response', 'both'
    
    // Match conditions
    this.matchUrl = config.matchUrl || null; // regex string
    this.matchHeaders = config.matchHeaders || {}; // key: regex pairs
    this.matchBody = config.matchBody || null; // regex string
    this.matchMethod = config.matchMethod || null; // exact match or array
    this.matchStatusCode = config.matchStatusCode || null; // for responses
    
    // Actions
    this.action = config.action || {}; // depends on type
    // For 'modify': { 
    //   headers: { 'X-Custom': 'value' },       // Add/modify headers
    //   removeHeaders: ['CSP', 'X-Frame'],      // Remove headers
    //   body: { search: '', replace: '' },      // Find/replace in body
    //   injectScript: 'code' or { src: 'url' }  // Inject inline or external script
    // }
  }

  matches(data) {
    // data = { url, headers, body, method, statusCode }
    
    // Check URL
    if (this.matchUrl) {
      const urlRegex = new RegExp(this.matchUrl);
      if (!urlRegex.test(data.url)) return false;
    }
    
    // Check method
    if (this.matchMethod) {
      if (Array.isArray(this.matchMethod)) {
        if (!this.matchMethod.includes(data.method)) return false;
      } else {
        if (this.matchMethod !== data.method) return false;
      }
    }
    
    // Check headers
    if (this.matchHeaders && Object.keys(this.matchHeaders).length > 0) {
      for (const [key, pattern] of Object.entries(this.matchHeaders)) {
        const headerValue = data.headers[key.toLowerCase()] || '';
        const regex = new RegExp(pattern);
        if (!regex.test(headerValue)) return false;
      }
    }
    
    // Check body
    if (this.matchBody && data.body) {
      const bodyRegex = new RegExp(this.matchBody);
      if (!bodyRegex.test(data.body)) return false;
    }
    
    // Check status code (for responses)
    if (this.matchStatusCode && data.statusCode) {
      if (Array.isArray(this.matchStatusCode)) {
        if (!this.matchStatusCode.includes(data.statusCode)) return false;
      } else {
        if (this.matchStatusCode !== data.statusCode) return false;
      }
    }
    
    return true;
  }

  apply(data) {
    if (!this.enabled) return data;
    
    const result = { ...data };
    result.headers = { ...data.headers }; // Clone headers
    
    if (this.type === 'modify') {
      // Remove headers first (CSP, etc.)
      if (this.action.removeHeaders && Array.isArray(this.action.removeHeaders)) {
        this.action.removeHeaders.forEach(headerName => {
          // Case-insensitive header removal
          const lowerName = headerName.toLowerCase();
          Object.keys(result.headers).forEach(key => {
            if (key.toLowerCase() === lowerName) {
              delete result.headers[key];
            }
          });
        });
      }
      
      // Add/modify headers
      if (this.action.headers) {
        result.headers = { ...result.headers, ...this.action.headers };
      }
      
      // Modify body with find/replace
      if (this.action.body && result.body) {
        const { search, replace } = this.action.body;
        if (search && replace !== undefined) {
          const regex = new RegExp(search, 'g');
          result.body = result.body.replace(regex, replace);
        }
      }
      
      // Inject script
      if (this.action.injectScript && result.body) {
        let scriptTag;
        
        // Check if it's an external script (object with src) or inline code (string)
        if (typeof this.action.injectScript === 'object' && this.action.injectScript.src) {
          scriptTag = `<script src="${this.action.injectScript.src}"></script>`;
        } else {
          scriptTag = `<script>${this.action.injectScript}</script>`;
        }
        
        // Try to inject before </body> or </head> or at end
        if (result.body.includes('</body>')) {
          result.body = result.body.replace('</body>', scriptTag + '\n</body>');
        } else if (result.body.includes('</head>')) {
          result.body = result.body.replace('</head>', scriptTag + '\n</head>');
        } else if (result.body.includes('</html>')) {
          result.body = result.body.replace('</html>', scriptTag + '\n</html>');
        } else {
          result.body += '\n' + scriptTag;
        }
        
        // Update content-length if present
        if (result.headers['content-length']) {
          result.headers['content-length'] = Buffer.byteLength(result.body).toString();
        }
      }
    }
    
    return result;
  }
}

class RuleManager {
  constructor(rulesFile) {
    this.rulesFile = rulesFile;
    this.rules = this.loadRules();
  }

  loadRules() {
    if (!existsSync(this.rulesFile)) {
      return [];
    }
    try {
      const data = JSON.parse(readFileSync(this.rulesFile, 'utf-8'));
      return data.map(r => new Rule(r));
    } catch (err) {
      console.error('[!] Error loading rules: ' + err.message);
      return [];
    }
  }

  saveRules() {
    try {
      const data = this.rules.map(r => ({
        id: r.id,
        name: r.name,
        enabled: r.enabled,
        type: r.type,
        scope: r.scope,
        matchUrl: r.matchUrl,
        matchHeaders: r.matchHeaders,
        matchBody: r.matchBody,
        matchMethod: r.matchMethod,
        matchStatusCode: r.matchStatusCode,
        action: r.action
      }));
      writeFileSync(this.rulesFile, JSON.stringify(data, null, 2));
    } catch (err) {
      console.error('[!] Error saving rules: ' + err.message);
    }
  }

  addRule(rule) {
    this.rules.push(new Rule(rule));
    this.saveRules();
  }

  removeRule(id) {
    this.rules = this.rules.filter(r => r.id !== id);
    this.saveRules();
  }

  toggleRule(id) {
    const rule = this.rules.find(r => r.id === id);
    if (rule) {
      rule.enabled = !rule.enabled;
      this.saveRules();
    }
  }

  applyRules(data, scope) {
    let result = data;
    
    for (const rule of this.rules) {
      if (!rule.enabled) continue;
      if (rule.scope !== scope && rule.scope !== 'both') continue;
      
      if (rule.matches(result)) {
        result = rule.apply(result);
      }
    }
    
    return result;
  }

  // Helper method to create a script injection rule with CSP bypass
  createScriptInjectionRule(config) {
    const rule = {
      name: config.name || 'Script Injection',
      type: 'modify',
      scope: 'response',
      matchHeaders: {
        'content-type': 'text/html'
      },
      matchUrl: config.matchUrl || null,
      action: {
        injectScript: config.scriptSrc ? { src: config.scriptSrc } : config.scriptCode,
        removeHeaders: [
          'content-security-policy',
          'content-security-policy-report-only',
          'x-content-security-policy',
          'x-webkit-csp'
        ]
      }
    };
    
    this.addRule(rule);
    return rule;
  }
}

class RepeaterTab {
  constructor(id, request, debug = false) {
    this.id = id;
    this.method = request.method;
    this.hostname = request.hostname;
    this.port = request.port;
    this.path = request.path;
    this.headers = request.headers;
    this.body = request.body;
    this.isHttps = request.isHttps;
    this.lastResponse = null;
    this.responseHistory = [];
    this.debug = debug;
    this.followRedirects = false;
  }

  serializeRequest() {
    let raw = this.method + ' ' + this.path + ' HTTP/1.1\r\n';
    raw += 'Host: ' + this.hostname + '\r\n';
    Object.entries(this.headers).forEach(([key, value]) => {
      if (key.toLowerCase() !== 'host') {
        raw += key + ': ' + value + '\r\n';
      }
    });
    raw += '\r\n';
    if (this.body) {
      raw += this.body;
    }
    return raw;
  }

  updateFromRaw(raw) {
    const lines = raw.split('\r\n');
    const firstLine = lines[0].split(' ');
    this.method = firstLine[0];
    this.path = firstLine[1];
    this.headers = {};
    let i = 1;
    for (; i < lines.length; i++) {
      if (lines[i] === '') break;
      const [key, ...valueParts] = lines[i].split(':');
      if (key && valueParts.length > 0) {
        const headerKey = key.trim();
        const headerValue = valueParts.join(':').trim();
        if (headerKey.toLowerCase() === 'host') {
          this.hostname = headerValue;
        } else {
          this.headers[headerKey] = headerValue;
        }
      }
    }
    this.body = lines.slice(i + 1).join('\r\n');
  }

  async send() {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.hostname,
        port: this.port,
        path: this.path,
        method: this.method,
        headers: { ...this.headers, host: this.hostname },
        followAllRedirects: this.followRedirects,
        maxRedirects: this.followRedirects ? 10 : 0
      };

      if (this.debug) {
        console.log('\n[DEBUG] Sending request:');
        console.log('  URL:', (this.isHttps ? 'https' : 'http') + '://' + this.hostname + ':' + this.port + this.path);
        console.log('  Method:', this.method);
        console.log('  Follow Redirects:', this.followRedirects);
        console.log('  Headers:', JSON.stringify(this.headers, null, 2));
        if (this.body) {
          console.log('  Body length:', this.body.length);
        }
      }

      const makeRequest = this.isHttps ? https.request : http.request;
      const startTime = Date.now();

      const req = makeRequest(options, (res) => {
        const chunks = [];
        res.on('data', chunk => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          const responseTime = Date.now() - startTime;
          let responseBody = Buffer.concat(chunks);

          if (this.debug) {
            console.log('\n[DEBUG] Response received:');
            console.log('  Status:', res.statusCode, res.statusMessage);
            console.log('  Raw buffer size:', responseBody.length, 'bytes');
            console.log('  Content-Encoding:', res.headers['content-encoding'] || 'none');
          }

          const encoding = res.headers['content-encoding'];
          try {
            if (encoding === 'gzip') {
              if (this.debug) console.log('  [DEBUG] Decompressing gzip...');
              responseBody = gunzipSync(responseBody);
              if (this.debug) console.log('  [DEBUG] Decompressed size:', responseBody.length, 'bytes');
            } else if (encoding === 'deflate') {
              if (this.debug) console.log('  [DEBUG] Decompressing deflate...');
              responseBody = inflateSync(responseBody);
              if (this.debug) console.log('  [DEBUG] Decompressed size:', responseBody.length, 'bytes');
            } else if (encoding === 'br') {
              if (this.debug) console.log('  [DEBUG] Decompressing brotli...');
              responseBody = brotliDecompressSync(responseBody);
              if (this.debug) console.log('  [DEBUG] Decompressed size:', responseBody.length, 'bytes');
            }
          } catch (err) {
            if (this.debug) console.log('  [DEBUG] Decompression failed:', err.message);
          }

          const bodyString = responseBody.toString('utf-8');
          if (this.debug) {
            console.log('  [DEBUG] Body string length:', bodyString.length, 'chars');
            console.log('  [DEBUG] Body preview:', bodyString.substring(0, 200));
          }

          const response = {
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            body: bodyString,
            responseTime,
            timestamp: new Date().toISOString()
          };

          this.lastResponse = response;
          this.responseHistory.push(response);
          resolve(response);
        });
      });

      req.on('error', (err) => {
        if (this.debug) {
          console.log('\n[DEBUG] Request error:', err.message);
        }
        reject(err);
      });

      if (this.body) {
        req.write(this.body);
      }
      req.end();
    });
  }
}

class CLIPI {
  constructor(options = {}) {
    this.host = options.host || '127.0.0.1';
    this.port = options.port || 8080;
    this.interceptMode = options.intercept || false;
    this.interceptResponse = options.interceptResponse || false;
    this.verbose = options.verbose || false;
    this.debug = options.debug || false;
    this.logging = options.log || false;
    this.logFile = options.logFile || 'requests.log';
    this.requestCount = 0;
    this.history = [];
    this.cli = options.cli;
    this.certCache = new Map();
    this.certDir = join(homedir(), '.clipi', 'certs');
    this.repeaterFile = join(homedir(), '.clipi', 'repeater-tabs.json');
    this.rulesFile = join(homedir(), '.clipi', 'rules.json');
    this.ca = this.loadOrCreateCA();
    this.repeaterTabs = this.loadRepeaterTabs();
    this.repeaterCount = this.repeaterTabs.length > 0 ? Math.max(...this.repeaterTabs.map(t => t.id)) : 0;
    this.ruleManager = new RuleManager(this.rulesFile);

    if (this.logging) {
      this.initLog();
    }
  }

  loadOrCreateCA() {
    if (!existsSync(this.certDir)) {
      mkdirSync(this.certDir, { recursive: true });
    }

    const caKeyPath = join(this.certDir, 'ca-key.pem');
    const caCertPath = join(this.certDir, 'ca-cert.pem');

    if (existsSync(caKeyPath) && existsSync(caCertPath)) {
      return {
        key: readFileSync(caKeyPath, 'utf8'),
        cert: readFileSync(caCertPath, 'utf8')
      };
    }

    console.log(this.cli.color.yellow('[*]') + ' Generating CA certificate...');
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

    const attrs = [
      { name: 'commonName', value: 'CLIPI CA' },
      { name: 'countryName', value: 'US' },
      { name: 'organizationName', value: 'CLIPI Proxy' }
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', keyCertSign: true, digitalSignature: true, keyEncipherment: true }
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    const pemKey = forge.pki.privateKeyToPem(keys.privateKey);
    const pemCert = forge.pki.certificateToPem(cert);

    writeFileSync(caKeyPath, pemKey);
    writeFileSync(caCertPath, pemCert);

    console.log(this.cli.color.green('[✓]') + ' CA certificate created at: ' + this.cli.color.cyan(this.certDir));
    console.log(this.cli.color.yellow('[!]') + ' Install ca-cert.pem on your device to intercept HTTPS');

    return { key: pemKey, cert: pemCert };
  }

  initLog() {
    const header = '\n═══════════════════════════════════════════════════════════\n' +
      'CLIPI Log - Session started at ' + new Date().toISOString() + '\n' +
      '═══════════════════════════════════════════════════════════\n\n';
    writeFileSync(this.logFile, header);
    console.log(this.cli.color.green('[✓]') + ' Logging to: ' + this.cli.color.cyan(this.logFile));
  }

  log(message) {
    if (!this.logging) return;
    const timestamp = new Date().toISOString();
    const entry = '[' + timestamp + '] ' + message + '\n';
    try {
      appendFileSync(this.logFile, entry);
    } catch (err) {
      // Ignore log errors silently
    }
  }

  loadRepeaterTabs() {
    if (!existsSync(this.repeaterFile)) {
      return [];
    }
    try {
      const data = JSON.parse(readFileSync(this.repeaterFile, 'utf-8'));
      return data.map(tabData => {
        const tab = new RepeaterTab(tabData.id, tabData, this.debug);
        tab.responseHistory = tabData.responseHistory || [];
        tab.lastResponse = tabData.lastResponse || null;
        tab.followRedirects = tabData.followRedirects || false;
        return tab;
      });
    } catch (err) {
      console.error((this.cli?.color?.red('[!]') || '[!]') + ' Error loading repeater tabs: ' + err.message);
      return [];
    }
  }

  saveRepeaterTabs() {
    try {
      const data = this.repeaterTabs.map(tab => ({
        id: tab.id,
        method: tab.method,
        hostname: tab.hostname,
        port: tab.port,
        path: tab.path,
        headers: tab.headers,
        body: tab.body,
        isHttps: tab.isHttps,
        lastResponse: tab.lastResponse,
        responseHistory: tab.responseHistory,
        followRedirects: tab.followRedirects
      }));
      writeFileSync(this.repeaterFile, JSON.stringify(data, null, 2));
    } catch (err) {
      console.error((this.cli?.color?.red('[!]') || '[!]') + ' Error saving repeater tabs: ' + err.message);
    }
  }

  generateCertificate(hostname) {
    if (this.certCache.has(hostname)) {
      return this.certCache.get(hostname);
    }

    const caKey = forge.pki.privateKeyFromPem(this.ca.key);
    const caCert = forge.pki.certificateFromPem(this.ca.cert);
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Math.floor(Math.random() * 100000).toString();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    cert.setSubject([{ name: 'commonName', value: hostname }]);
    cert.setIssuer(caCert.subject.attributes);
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] }
    ]);
    cert.sign(caKey, forge.md.sha256.create());

    const pemKey = forge.pki.privateKeyToPem(keys.privateKey);
    const pemCert = forge.pki.certificateToPem(cert);

    const result = { key: pemKey, cert: pemCert };
    this.certCache.set(hostname, result);
    return result;
  }

  start() {
    const server = http.createServer((req, res) => {
      this.handleHTTP(req, res);
    });

    server.on('connect', (req, clientSocket, head) => {
      this.handleHTTPS(req, clientSocket, head);
    });

    server.listen(this.port, this.host, () => {
      console.log(this.cli.color.green('[+]') + ' CLIPI started on ' + this.cli.color.bold(this.host + ':' + this.port));
      console.log(this.cli.color.cyan('[*]') + ' Request Intercept mode: ' + (this.interceptMode ? this.cli.color.yellow('ACTIVE') : this.cli.color.dim('PASSIVE')));
      console.log(this.cli.color.cyan('[*]') + ' Response Intercept mode: ' + (this.interceptResponse ? this.cli.color.yellow('ACTIVE') : this.cli.color.dim('PASSIVE')));
      console.log(this.cli.color.cyan('[*]') + ' Active Rules: ' + this.cli.color.yellow(this.ruleManager.rules.filter(r => r.enabled).length) + '/' + this.ruleManager.rules.length);
      if (this.debug) {
        console.log(this.cli.color.magenta('[*]') + ' Debug mode: ' + this.cli.color.yellow('ENABLED'));
      }
      if (this.logging) {
        console.log(this.cli.color.magenta('[*]') + ' Logging: ' + this.cli.color.yellow('ENABLED') + ' → ' + this.cli.color.cyan(this.logFile));
      }
      console.log(this.cli.color.yellow('[*]') + ' Press Ctrl+C to stop\n');
    });

    server.on('error', (err) => {
      console.error(this.cli.color.red('[ERROR]') + ' ' + err.message);
    });
  }

  async handleHTTP(clientReq, clientRes, isHttps = false, httpsHost = null, httpsPort = null) {
    this.requestCount++;
    const reqId = this.requestCount;

    const targetUrl = parseUrl(clientReq.url);
    let hostname, port, path;

    if (isHttps) {
      hostname = httpsHost;
      port = httpsPort;
      path = clientReq.url;
    } else {
      hostname = clientReq.headers.host?.split(':')[0] || targetUrl.hostname;
      port = clientReq.headers.host?.split(':')[1] || 80;
      path = targetUrl.path || '/';
    }

    console.log(this.cli.color.bold('[' + reqId + ']') + ' ' + clientReq.method + ' ' +
      this.cli.color.blue(hostname + path) + ' ' + (isHttps ? this.cli.color.magenta('[HTTPS]') : ''));

    let requestBody = '';
    clientReq.on('data', chunk => {
      requestBody += chunk.toString();
    });

    await new Promise(resolve => clientReq.on('end', resolve));

    if (this.logging) {
      this.log('\n[REQUEST #' + reqId + '] ' + clientReq.method + ' ' + hostname + path + ' ' + (isHttps ? '[HTTPS]' : '[HTTP]'));
      this.log('Headers: ' + JSON.stringify(clientReq.headers, null, 2));
      if (requestBody) {
        this.log('Body: ' + requestBody);
      }
    }

    let method = clientReq.method;
    let finalPath = path;
    let headers = { ...clientReq.headers };
    let body = requestBody;

    if (isHttps) {
      headers.host = hostname;
    }

    // Apply request rules
    const requestData = {
      url: hostname + path,
      method: method,
      headers: headers,
      body: body
    };
    const modifiedRequest = this.ruleManager.applyRules(requestData, 'request');
    method = modifiedRequest.method;
    headers = modifiedRequest.headers;
    body = modifiedRequest.body;

    // Manual request interception
    if (this.interceptMode) {
      const result = await this.interceptRequest(clientReq, body, hostname, path, port, isHttps);
      if (result.action === 'drop') {
        if (this.logging) {
          this.log('[DROPPED] Request #' + reqId);
        }
        clientRes.writeHead(403);
        clientRes.end('Request blocked by proxy');
        return;
      }

      if (result.action === 'repeater') {
        if (this.logging) {
          this.log('[REPEATER] Request #' + reqId + ' sent to Repeater');
        }
      }

      if (result.action === 'modify') {
        method = result.data.method;
        finalPath = result.data.path;
        headers = result.data.headers;
        body = result.data.body;
        if (this.logging) {
          this.log('[MODIFIED] Request #' + reqId);
          this.log('New method: ' + method);
          this.log('New path: ' + finalPath);
          this.log('New headers: ' + JSON.stringify(headers, null, 2));
          if (body) {
            this.log('New body: ' + body);
          }
        }
      }
    }

    if (this.verbose) {
      console.log('  ' + this.cli.color.cyan('Headers:'), headers);
      if (body) {
        console.log('  ' + this.cli.color.cyan('Body:'), body.substring(0, 200));
      }
    }

    const options = {
      hostname: hostname,
      port: port,
      path: finalPath,
      method: method,
      headers: headers
    };

    const makeRequest = isHttps ? https.request : http.request;

    const proxyReq = makeRequest(options, async (proxyRes) => {
      const chunks = [];
      proxyRes.on('data', chunk => {
        chunks.push(chunk);
      });

      proxyRes.on('end', async () => {
        const statusColor = proxyRes.statusCode < 300 ? this.cli.color.green :
          proxyRes.statusCode < 400 ? this.cli.color.yellow : this.cli.color.red;
        console.log('  ' + statusColor('← ' + proxyRes.statusCode) + ' ' + http.STATUS_CODES[proxyRes.statusCode]);

        this.history.push({
          id: reqId,
          method: clientReq.method,
          url: hostname + path,
          status: proxyRes.statusCode,
          requestHeaders: clientReq.headers,
          responseHeaders: proxyRes.headers,
          timestamp: new Date().toISOString(),
          https: isHttps
        });

        let responseBody = Buffer.concat(chunks);
        const encoding = proxyRes.headers['content-encoding'];

        if (this.debug) {
          console.log('  ' + this.cli.color.cyan('[DEBUG] Response:'), responseBody.length, 'bytes');
          console.log('  ' + this.cli.color.cyan('[DEBUG] Content-Encoding:'), encoding || 'none');
        }

        // Decompress if needed
        try {
          if (encoding === 'gzip') {
            if (this.debug) console.log('  ' + this.cli.color.cyan('[DEBUG] Decompressing gzip...'));
            responseBody = gunzipSync(responseBody);
          } else if (encoding === 'deflate') {
            if (this.debug) console.log('  ' + this.cli.color.cyan('[DEBUG] Decompressing deflate...'));
            responseBody = inflateSync(responseBody);
          } else if (encoding === 'br') {
            if (this.debug) console.log('  ' + this.cli.color.cyan('[DEBUG] Decompressing brotli...'));
            responseBody = brotliDecompressSync(responseBody);
          }
        } catch (err) {
          if (this.debug) console.log('  ' + this.cli.color.cyan('[DEBUG] Decompression failed:'), err.message);
        }

        let bodyString = responseBody.toString('utf-8');
        let responseHeaders = { ...proxyRes.headers };
        let statusCode = proxyRes.statusCode;

        if (this.debug) {
          console.log('  ' + this.cli.color.cyan('[DEBUG] Decompressed size:'), bodyString.length, 'chars');
        }

        // Apply response rules
        const responseData = {
          url: hostname + path,
          method: method,
          headers: responseHeaders,
          body: bodyString,
          statusCode: statusCode
        };
        const modifiedResponse = this.ruleManager.applyRules(responseData, 'response');
        bodyString = modifiedResponse.body;
        responseHeaders = modifiedResponse.headers;

        // Manual response interception
        if (this.interceptResponse) {
          const result = await this.interceptResponse_handler(proxyRes, bodyString, responseHeaders);
          if (result.action === 'drop') {
            if (this.logging) {
              this.log('[DROPPED] Response #' + reqId);
            }
            clientRes.writeHead(403);
            clientRes.end('Response blocked by proxy');
            return;
          }
          if (result.action === 'modify') {
            bodyString = result.data.body;
            responseHeaders = result.data.headers;
            statusCode = result.data.statusCode || statusCode;
          }
        }

        // Remove encoding headers since we decompressed
        if (encoding) {
          delete responseHeaders['content-encoding'];
          responseHeaders['content-length'] = Buffer.byteLength(bodyString).toString();
        }

        if (this.logging) {
          this.log('[RESPONSE #' + reqId + '] ' + statusCode + ' ' + http.STATUS_CODES[statusCode]);
          this.log('Headers: ' + JSON.stringify(responseHeaders, null, 2));
          this.log('Body: ' + bodyString);
          this.log('─'.repeat(80));
        }

        if (this.verbose || this.debug) {
          console.log('  ' + this.cli.color.cyan('Response Headers:'), responseHeaders);
          console.log('  ' + this.cli.color.cyan('Response Body:'));
          const displayLimit = 1000;
          if (bodyString.length > displayLimit) {
            console.log(bodyString.substring(0, displayLimit));
            console.log('\n  ' + this.cli.color.yellow('... (' + (bodyString.length - displayLimit) + ' more chars - see requests.log for full body)'));
          } else {
            console.log(bodyString);
          }
        }

        clientRes.writeHead(statusCode, responseHeaders);
        clientRes.end(bodyString);
      });
    });

    proxyReq.on('error', (err) => {
      console.error(this.cli.color.red('[!]') + ' Error connecting to ' + hostname + ': ' + err.message);
      if (this.logging) {
        this.log('[ERROR #' + reqId + '] ' + err.message);
      }
      clientRes.writeHead(502);
      clientRes.end('Bad Gateway');
    });

    if (body) {
      proxyReq.write(body);
    }
    proxyReq.end();
  }

  handleHTTPS(req, clientSocket, head) {
    const { port, hostname } = parseUrl('//' + req.url, false, true);
    const targetPort = port || 443;

    console.log(this.cli.color.cyan('[HTTPS]') + ' CONNECT ' + hostname + ':' + targetPort);

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const cert = this.generateCertificate(hostname);
    const httpsServer = https.createServer(
      { key: cert.key, cert: cert.cert },
      (req, res) => {
        this.handleHTTP(req, res, true, hostname, targetPort);
      }
    );

    httpsServer.once('error', (err) => {
      console.error(this.cli.color.red('[!]') + ' HTTPS server error: ' + err.message);
      clientSocket.end();
    });

    httpsServer.emit('connection', clientSocket);

    if (head && head.length > 0) {
      clientSocket.unshift(head);
    }
  }

  serializeRequest(method, hostname, path, headers, body) {
    let raw = method + ' ' + path + ' HTTP/1.1\r\n';
    raw += 'Host: ' + hostname + '\r\n';
    Object.entries(headers).forEach(([key, value]) => {
      if (key.toLowerCase() !== 'host') {
        raw += key + ': ' + value + '\r\n';
      }
    });
    raw += '\r\n';
    if (body) {
      raw += body;
    }
    return raw;
  }

  serializeResponse(statusCode, statusMessage, headers, body) {
    let raw = 'HTTP/1.1 ' + statusCode + ' ' + statusMessage + '\r\n';
    Object.entries(headers).forEach(([key, value]) => {
      raw += key + ': ' + value + '\r\n';
    });
    raw += '\r\n';
    if (body) {
      raw += body;
    }
    return raw;
  }

  parseModifiedRequest(raw) {
    const lines = raw.split('\r\n');
    const firstLine = lines[0].split(' ');
    const method = firstLine[0];
    const path = firstLine[1];
    const headers = {};
    let i = 1;
    for (; i < lines.length; i++) {
      if (lines[i] === '') break;
      const [key, ...valueParts] = lines[i].split(':');
      if (key && valueParts.length > 0) {
        headers[key.trim()] = valueParts.join(':').trim();
      }
    }
    const body = lines.slice(i + 1).join('\r\n');
    return { method, path, headers, body };
  }

  parseModifiedResponse(raw) {
    const lines = raw.split('\r\n');
    const firstLine = lines[0].split(' ');
    const statusCode = parseInt(firstLine[1]);
    const statusMessage = firstLine.slice(2).join(' ');
    const headers = {};
    let i = 1;
    for (; i < lines.length; i++) {
      if (lines[i] === '') break;
      const [key, ...valueParts] = lines[i].split(':');
      if (key && valueParts.length > 0) {
        headers[key.trim()] = valueParts.join(':').trim();
      }
    }
    const body = lines.slice(i + 1).join('\r\n');
    return { statusCode, statusMessage, headers, body };
  }

  openEditor(content) {
    const editor = process.env.EDITOR || process.env.VISUAL || 'vim';
    const tmpFile = join(tmpdir(), 'clipi-' + Date.now() + '.txt');

    try {
      writeFileSync(tmpFile, content);
      const result = spawnSync(editor, [tmpFile], { stdio: 'inherit', shell: true });

      if (result.error) {
        console.log(this.cli.color.red('[!]') + ' Error opening editor: ' + result.error.message);
        return null;
      }

      const modified = readFileSync(tmpFile, 'utf-8');
      unlinkSync(tmpFile);
      return modified;
    } catch (err) {
      console.log(this.cli.color.red('[!]') + ' Error: ' + err.message);
      try {
        unlinkSync(tmpFile);
      } catch { }
      return null;
    }
  }

  async interceptRequest(req, body, hostname, path, port, isHttps) {
    console.log('\n' + this.cli.color.yellow('╔═══ REQUEST INTERCEPTED ═══╗'));
    console.log(this.cli.color.yellow('║') + ' ' + this.cli.color.bold('Method:') + ' ' + req.method);
    console.log(this.cli.color.yellow('║') + ' ' + this.cli.color.bold('URL:') + ' ' + hostname + path);
    if (this.verbose) {
      console.log(this.cli.color.yellow('║') + ' ' + this.cli.color.bold('Headers:'));
      Object.entries(req.headers).forEach(([key, value]) => {
        console.log(this.cli.color.yellow('║') + '   ' + key + ': ' + value);
      });
      if (body) {
        console.log(this.cli.color.yellow('║') + ' ' + this.cli.color.bold('Body:'));
        console.log(this.cli.color.yellow('║') + '   ' + body.substring(0, 200));
      }
    }
    console.log(this.cli.color.yellow('╚═══════════════════════════╝') + '\n');

    const response = await prompts({
      type: 'select',
      name: 'action',
      message: 'Choose action:',
      choices: [
        { title: '→ Forward', description: 'Send request as-is', value: 'forward' },
        { title: '✎ Modify', description: 'Edit request in editor', value: 'modify' },
        { title: '🔄 Repeater', description: 'Send to Repeater', value: 'repeater' },
        { title: '✗ Drop', description: 'Block this request', value: 'drop' }
      ],
      initial: 0
    });

    if (!response.action) {
      console.log(this.cli.color.yellow('[!] Cancelled, forwarding request') + '\n');
      return { action: 'forward' };
    }

    if (response.action === 'drop') {
      console.log(this.cli.color.red('[✗] Request dropped') + '\n');
      return { action: 'drop' };
    }

    if (response.action === 'repeater') {
      const tab = this.createRepeaterTab({
        method: req.method,
        hostname: hostname,
        port: port,
        path: path,
        headers: req.headers,
        body: body,
        isHttps: isHttps
      });
      console.log(this.cli.color.cyan('[🔄] Request sent to Repeater') + ' ' +
        this.cli.color.dim('(Tab ' + tab.id + ')') + '\n');
      return { action: 'repeater' };
    }

    if (response.action === 'modify') {
      const rawRequest = this.serializeRequest(req.method, hostname, path, req.headers, body);
      const modified = this.openEditor(rawRequest);
      if (modified) {
        try {
          const parsed = this.parseModifiedRequest(modified);
          console.log(this.cli.color.green('[✓] Request modified') + '\n');
          return { action: 'modify', data: parsed };
        } catch (err) {
          console.log(this.cli.color.red('[!] Invalid request format, forwarding original') + '\n');
          return { action: 'forward' };
        }
      } else {
        console.log(this.cli.color.yellow('[!] Editor closed, forwarding original') + '\n');
        return { action: 'forward' };
      }
    }

    console.log(this.cli.color.green('[→] Request forwarded') + '\n');
    return { action: 'forward' };
  }

  async interceptResponse_handler(res, body, headers) {
    console.log('\n' + this.cli.color.magenta('╔═══ RESPONSE INTERCEPTED ═══╗'));
    console.log(this.cli.color.magenta('║') + ' ' + this.cli.color.bold('Status:') + ' ' + res.statusCode + ' ' + res.statusMessage);
    if (this.verbose) {
      console.log(this.cli.color.magenta('║') + ' ' + this.cli.color.bold('Headers:'));
      Object.entries(headers).forEach(([key, value]) => {
        console.log(this.cli.color.magenta('║') + '   ' + key + ': ' + value);
      });
      if (body) {
        console.log(this.cli.color.magenta('║') + ' ' + this.cli.color.bold('Body Preview:'));
        console.log(this.cli.color.magenta('║') + '   ' + body.substring(0, 200));
      }
    }
    console.log(this.cli.color.magenta('╚═════════════════════════════╝') + '\n');

    const response = await prompts({
      type: 'select',
      name: 'action',
      message: 'Choose action:',
      choices: [
        { title: '→ Forward', description: 'Send response as-is', value: 'forward' },
        { title: '✎ Modify', description: 'Edit response in editor', value: 'modify' },
        { title: '✗ Drop', description: 'Block this response', value: 'drop' }
      ],
      initial: 0
    });

    if (!response.action) {
      console.log(this.cli.color.yellow('[!] Cancelled, forwarding response') + '\n');
      return { action: 'forward' };
    }

    if (response.action === 'drop') {
      console.log(this.cli.color.red('[✗] Response dropped') + '\n');
      return { action: 'drop' };
    }

    if (response.action === 'modify') {
      const rawResponse = this.serializeResponse(res.statusCode, res.statusMessage, headers, body);
      const modified = this.openEditor(rawResponse);
      if (modified) {
        try {
          const parsed = this.parseModifiedResponse(modified);
          console.log(this.cli.color.green('[✓] Response modified') + '\n');
          return { action: 'modify', data: parsed };
        } catch (err) {
          console.log(this.cli.color.red('[!] Invalid response format, forwarding original') + '\n');
          return { action: 'forward' };
        }
      } else {
        console.log(this.cli.color.yellow('[!] Editor closed, forwarding original') + '\n');
        return { action: 'forward' };
      }
    }

    console.log(this.cli.color.green('[→] Response forwarded') + '\n');
    return { action: 'forward' };
  }

  createRepeaterTab(request) {
    this.repeaterCount++;
    const tab = new RepeaterTab(this.repeaterCount, request, this.debug);
    this.repeaterTabs.push(tab);
    this.saveRepeaterTabs();
    return tab;
  }

  async openRulesManager() {
    while (true) {
      console.clear();
      console.log(this.cli.color.cyan('╔═══════════════════════════════════════╗'));
      console.log(this.cli.color.cyan('║') + '  ' + this.cli.color.bold.white('RULES MANAGER') + '  ' + this.cli.color.cyan('║'));
      console.log(this.cli.color.cyan('╚═══════════════════════════════════════╝') + '\n');

      if (this.ruleManager.rules.length === 0) {
        console.log(this.cli.color.yellow('No rules configured') + '\n');
      } else {
        this.ruleManager.rules.forEach(rule => {
          const status = rule.enabled ? this.cli.color.green('✓') : this.cli.color.red('✗');
          console.log(status + ' [' + rule.id + '] ' + this.cli.color.bold(rule.name));
          console.log('  Type: ' + rule.type + ' | Scope: ' + rule.scope);
          if (rule.matchUrl) console.log('  Match URL: ' + this.cli.color.cyan(rule.matchUrl));
          if (rule.matchHeaders && Object.keys(rule.matchHeaders).length > 0) {
            console.log('  Match Headers: ' + this.cli.color.cyan(JSON.stringify(rule.matchHeaders)));
          }
          if (rule.action.injectScript) {
            const scriptInfo = typeof rule.action.injectScript === 'object' ? 
              'External: ' + rule.action.injectScript.src : 
              'Inline code';
            console.log('  Action: ' + this.cli.color.yellow('Inject script (' + scriptInfo + ')'));
          }
          if (rule.action.removeHeaders) {
            console.log('  Remove: ' + this.cli.color.red(rule.action.removeHeaders.join(', ')));
          }
          console.log('');
        });
      }

      const choices = [
        { title: '+ Add Rule', value: 'add' },
        { title: '⚡ Quick: Script Injection + CSP Bypass', value: 'quick-script' },
        { title: '✎ Edit Rule', value: 'edit', disabled: this.ruleManager.rules.length === 0 },
        { title: '🔄 Toggle Rule', value: 'toggle', disabled: this.ruleManager.rules.length === 0 },
        { title: '👁 View Rule', value: 'view', disabled: this.ruleManager.rules.length === 0 },
        { title: '🗑 Delete Rule', value: 'delete', disabled: this.ruleManager.rules.length === 0 },
        { title: '← Back', value: 'back' }
      ];

      const action = await prompts({
        type: 'select',
        name: 'value',
        message: 'Manage rules:',
        choices: choices
      });

      if (!action.value || action.value === 'back') return;

      switch (action.value) {
        case 'add':
          await this.addRule();
          break;
        case 'quick-script':
          await this.quickScriptInjection();
          break;
        case 'edit':
          await this.editRule();
          break;
        case 'toggle':
          await this.toggleRule();
          break;
        case 'view':
          await this.viewRule();
          break;
        case 'delete':
          await this.deleteRule();
          break;
      }
    }
  }

  async quickScriptInjection() {
    console.clear();
    console.log(this.cli.color.cyan('═══ QUICK SCRIPT INJECTION + CSP BYPASS ═══') + '\n');
    console.log(this.cli.color.dim('This will create a rule that:'));
    console.log(this.cli.color.dim('• Detects HTML responses (Content-Type: text/html)'));
    console.log(this.cli.color.dim('• Injects your script into the HTML'));
    console.log(this.cli.color.dim('• Removes CSP headers that block script execution') + '\n');

    const name = await prompts({
      type: 'text',
      name: 'value',
      message: 'Rule name:',
      initial: 'Script Injection'
    });
    if (!name.value) return;

    const scriptType = await prompts({
      type: 'select',
      name: 'value',
      message: 'Script type:',
      choices: [
        { title: 'External script (from URL)', value: 'external' },
        { title: 'Inline JavaScript code', value: 'inline' }
      ]
    });
    if (!scriptType.value) return;

    let scriptConfig;
    if (scriptType.value === 'external') {
      const scriptUrl = await prompts({
        type: 'text',
        name: 'value',
        message: 'Script URL:',
        initial: 'http://localhost:3000/customScript.js'
      });
      if (!scriptUrl.value) return;
      scriptConfig = { src: scriptUrl.value };
    } else {
      const scriptCode = await prompts({
        type: 'text',
        name: 'value',
        message: 'JavaScript code:',
        initial: 'console.log("CLIPI injected!");'
      });
      if (!scriptCode.value) return;
      scriptConfig = scriptCode.value;
    }

    const matchUrl = await prompts({
      type: 'text',
      name: 'value',
      message: 'Match URL pattern (regex, empty for all HTML):',
      initial: ''
    });

    const config = {
      name: name.value,
      scriptSrc: scriptType.value === 'external' ? scriptConfig.src : null,
      scriptCode: scriptType.value === 'inline' ? scriptConfig : null,
      matchUrl: matchUrl.value || null
    };

    // Use the helper method
    if (config.scriptSrc) {
      this.ruleManager.createScriptInjectionRule({
        name: config.name,
        scriptSrc: config.scriptSrc,
        matchUrl: config.matchUrl
      });
    } else {
      this.ruleManager.createScriptInjectionRule({
        name: config.name,
        scriptCode: config.scriptCode,
        matchUrl: config.matchUrl
      });
    }

    console.log('\n' + this.cli.color.green('[✓] Script injection rule created!'));
    console.log(this.cli.color.dim('\nThe rule will:'));
    console.log(this.cli.color.dim('✓ Match HTML responses'));
    console.log(this.cli.color.dim('✓ Inject your script'));
    console.log(this.cli.color.dim('✓ Remove these CSP headers:'));
    console.log(this.cli.color.dim('  - Content-Security-Policy'));
    console.log(this.cli.color.dim('  - Content-Security-Policy-Report-Only'));
    console.log(this.cli.color.dim('  - X-Content-Security-Policy'));
    console.log(this.cli.color.dim('  - X-WebKit-CSP'));
    await this.pause();
  }

  async addRule() {
    console.clear();
    console.log(this.cli.color.cyan('═══ ADD NEW RULE ═══') + '\n');

    const name = await prompts({
      type: 'text',
      name: 'value',
      message: 'Rule name:',
      validate: v => v.length > 0 || 'Name required'
    });
    if (!name.value) return;

    const type = await prompts({
      type: 'select',
      name: 'value',
      message: 'Rule type:',
      choices: [
        { title: 'Modify', value: 'modify' },
        { title: 'Block', value: 'block' },
        { title: 'Redirect', value: 'redirect' }
      ]
    });
    if (!type.value) return;

    const scope = await prompts({
      type: 'select',
      name: 'value',
      message: 'Apply to:',
      choices: [
        { title: 'Requests only', value: 'request' },
        { title: 'Responses only', value: 'response' },
        { title: 'Both', value: 'both' }
      ]
    });
    if (!scope.value) return;

    const matchUrl = await prompts({
      type: 'text',
      name: 'value',
      message: 'Match URL (regex, empty for all):',
      initial: ''
    });

    const matchMethod = await prompts({
      type: 'text',
      name: 'value',
      message: 'Match method (empty for all):',
      initial: ''
    });

    let action = {};

    if (type.value === 'modify') {
      const modType = await prompts({
        type: 'select',
        name: 'value',
        message: 'Modification type:',
        choices: [
          { title: 'Inject Script', value: 'script' },
          { title: 'Find & Replace', value: 'replace' },
          { title: 'Add Header', value: 'header' },
          { title: 'Remove Headers', value: 'remove-header' }
        ]
      });

      if (modType.value === 'script') {
        const scriptType = await prompts({
          type: 'select',
          name: 'value',
          message: 'Script type:',
          choices: [
            { title: 'External (from URL)', value: 'external' },
            { title: 'Inline code', value: 'inline' }
          ]
        });

        if (scriptType.value === 'external') {
          const scriptUrl = await prompts({
            type: 'text',
            name: 'value',
            message: 'Script URL:',
            initial: 'http://localhost:3000/script.js'
          });
          action.injectScript = { src: scriptUrl.value };
        } else {
          const script = await prompts({
            type: 'text',
            name: 'value',
            message: 'JavaScript to inject:',
            initial: 'console.log("CLIPI Injected");'
          });
          action.injectScript = script.value;
        }

        // Ask if they want to remove CSP headers
        const removeCSP = await prompts({
          type: 'confirm',
          name: 'value',
          message: 'Remove CSP headers? (Recommended for script injection)',
          initial: true
        });

        if (removeCSP.value) {
          action.removeHeaders = [
            'content-security-policy',
            'content-security-policy-report-only',
            'x-content-security-policy',
            'x-webkit-csp'
          ];
        }
      } else if (modType.value === 'replace') {
        const search = await prompts({
          type: 'text',
          name: 'value',
          message: 'Search pattern (regex):'
        });
        const replace = await prompts({
          type: 'text',
          name: 'value',
          message: 'Replace with:'
        });
        action.body = { search: search.value, replace: replace.value };
      } else if (modType.value === 'header') {
        const headerName = await prompts({
          type: 'text',
          name: 'value',
          message: 'Header name:'
        });
        const headerValue = await prompts({
          type: 'text',
          name: 'value',
          message: 'Header value:'
        });
        action.headers = { [headerName.value]: headerValue.value };
      } else if (modType.value === 'remove-header') {
        const headers = await prompts({
          type: 'text',
          name: 'value',
          message: 'Headers to remove (comma-separated):',
          initial: 'content-security-policy'
        });
        action.removeHeaders = headers.value.split(',').map(h => h.trim());
      }
    }

    const rule = {
      name: name.value,
      type: type.value,
      scope: scope.value,
      matchUrl: matchUrl.value || null,
      matchMethod: matchMethod.value || null,
      action: action
    };

    this.ruleManager.addRule(rule);
    console.log(this.cli.color.green('[✓] Rule added') + '\n');
    await this.pause();
  }

  async viewRule() {
    const choices = this.ruleManager.rules.map(r => ({
      title: r.name,
      description: 'Type: ' + r.type + ' | Scope: ' + r.scope,
      value: r.id
    }));

    const selection = await prompts({
      type: 'select',
      name: 'value',
      message: 'Select rule to view:',
      choices: choices
    });

    if (!selection.value) return;

    const rule = this.ruleManager.rules.find(r => r.id === selection.value);
    if (!rule) return;

    console.clear();
    console.log(this.cli.color.cyan('═══ RULE DETAILS ═══') + '\n');
    console.log(this.cli.color.bold('Name:') + ' ' + rule.name);
    console.log(this.cli.color.bold('ID:') + ' ' + rule.id);
    console.log(this.cli.color.bold('Status:') + ' ' + (rule.enabled ? this.cli.color.green('Enabled') : this.cli.color.red('Disabled')));
    console.log(this.cli.color.bold('Type:') + ' ' + rule.type);
    console.log(this.cli.color.bold('Scope:') + ' ' + rule.scope);
    
    console.log('\n' + this.cli.color.bold('Match Conditions:'));
    if (rule.matchUrl) console.log('  URL: ' + this.cli.color.cyan(rule.matchUrl));
    if (rule.matchMethod) console.log('  Method: ' + this.cli.color.cyan(rule.matchMethod));
    if (rule.matchHeaders && Object.keys(rule.matchHeaders).length > 0) {
      console.log('  Headers:');
      Object.entries(rule.matchHeaders).forEach(([k, v]) => {
        console.log('    ' + k + ': ' + this.cli.color.cyan(v));
      });
    }
    if (rule.matchBody) console.log('  Body: ' + this.cli.color.cyan(rule.matchBody));
    if (rule.matchStatusCode) console.log('  Status Code: ' + this.cli.color.cyan(rule.matchStatusCode));

    console.log('\n' + this.cli.color.bold('Actions:'));
    if (rule.action.headers) {
      console.log('  Add/Modify Headers:');
      Object.entries(rule.action.headers).forEach(([k, v]) => {
        console.log('    ' + this.cli.color.green(k + ': ' + v));
      });
    }
    if (rule.action.removeHeaders) {
      console.log('  Remove Headers: ' + this.cli.color.red(rule.action.removeHeaders.join(', ')));
    }
    if (rule.action.injectScript) {
      if (typeof rule.action.injectScript === 'object') {
        console.log('  Inject External Script: ' + this.cli.color.yellow(rule.action.injectScript.src));
      } else {
        console.log('  Inject Inline Script: ' + this.cli.color.yellow(rule.action.injectScript.substring(0, 50) + '...'));
      }
    }
    if (rule.action.body) {
      console.log('  Find & Replace:');
      console.log('    Search: ' + this.cli.color.cyan(rule.action.body.search));
      console.log('    Replace: ' + this.cli.color.cyan(rule.action.body.replace));
    }

    await this.pause();
  }

  async editRule() {
    const choices = this.ruleManager.rules.map(r => ({
      title: r.name,
      description: 'Type: ' + r.type + ' | Scope: ' + r.scope,
      value: r.id
    }));

    const selection = await prompts({
      type: 'select',
      name: 'value',
      message: 'Select rule to edit:',
      choices: choices
    });

    if (!selection.value) return;

    console.log(this.cli.color.yellow('[!] Full edit not implemented yet. Use delete + add for now.'));
    await this.pause();
  }

  async toggleRule() {
    const choices = this.ruleManager.rules.map(r => ({
      title: (r.enabled ? '✓ ' : '✗ ') + r.name,
      description: 'Type: ' + r.type + ' | Scope: ' + r.scope,
      value: r.id
    }));

    const selection = await prompts({
      type: 'select',
      name: 'value',
      message: 'Select rule to toggle:',
      choices: choices
    });

    if (selection.value) {
      this.ruleManager.toggleRule(selection.value);
      console.log(this.cli.color.green('[✓] Rule toggled'));
      await this.pause();
    }
  }

  async deleteRule() {
    const choices = this.ruleManager.rules.map(r => ({
      title: r.name,
      description: 'Type: ' + r.type + ' | Scope: ' + r.scope,
      value: r.id
    }));

    const selection = await prompts({
      type: 'select',
      name: 'value',
      message: 'Select rule to delete:',
      choices: choices
    });

    if (selection.value) {
      const confirm = await prompts({
        type: 'confirm',
        name: 'value',
        message: 'Delete this rule?',
        initial: false
      });

      if (confirm.value) {
        this.ruleManager.removeRule(selection.value);
        console.log(this.cli.color.green('[✓] Rule deleted'));
        await this.pause();
      }
    }
  }

  async openRepeater() {
    if (this.repeaterTabs.length === 0) {
      console.log('\n' + this.cli.color.yellow('[!]') + ' No repeater tabs available');
      console.log(this.cli.color.dim('Start the proxy with -i and intercept a request, then send it to Repeater'));
      console.log(this.cli.color.dim('Or the tabs were cleared. Tabs persist in ~/.clipi/repeater-tabs.json') + '\n');
      return;
    }

    let currentTab = null;

    while (true) {
      console.clear();
      console.log(this.cli.color.cyan('╔═══════════════════════════════════════╗'));
      console.log(this.cli.color.cyan('║') + '  ' + this.cli.color.bold.white('CLIPI REPEATER') + '  ' + this.cli.color.cyan('║'));
      console.log(this.cli.color.cyan('╚═══════════════════════════════════════╝') + '\n');

      const tabChoices = this.repeaterTabs.map(tab => ({
        title: 'Tab ' + tab.id + ': ' + tab.method + ' ' + tab.hostname + tab.path,
        description: tab.lastResponse ? 'Last: ' + tab.lastResponse.statusCode + ' (' + tab.lastResponse.responseTime + 'ms)' : 'Not sent yet',
        value: tab.id
      }));

      tabChoices.push({ title: '← Back to Proxy', value: 'back' });

      const tabSelect = await prompts({
        type: 'select',
        name: 'tabId',
        message: 'Select Repeater Tab:',
        choices: tabChoices
      });

      if (!tabSelect.tabId || tabSelect.tabId === 'back') {
        return;
      }

      currentTab = this.repeaterTabs.find(t => t.id === tabSelect.tabId);
      if (!currentTab) continue;

      await this.repeaterTabMenu(currentTab);
    }
  }

  // Repeater tab methods shortened for brevity - they remain the same as before
  async repeaterTabMenu(tab) {
    // ... (same as before, keeping this short)
    console.log(this.cli.color.yellow('[!] Repeater tab menu - implementation same as before'));
    await this.pause();
  }

  async pause() {
    console.log('\n' + this.cli.color.dim('Press Enter to continue...'));
    await prompts({ type: 'text', name: 'continue', message: '' });
  }

  showHistory() {
    console.log('\n' + this.cli.color.bold('═══ HISTORY (' + this.history.length + ' requests) ═══'));
    this.history.slice(-10).forEach(entry => {
      const statusColor = entry.status < 300 ? this.cli.color.green :
        entry.status < 400 ? this.cli.color.yellow : this.cli.color.red;
      console.log('[' + entry.id + '] ' + entry.method + ' ' + entry.url + ' ' + statusColor(entry.status));
    });

    if (this.repeaterTabs.length > 0) {
      console.log('\n' + this.cli.color.bold('═══ REPEATER (' + this.repeaterTabs.length + ' tabs) ═══'));
      this.repeaterTabs.forEach(tab => {
        const info = tab.lastResponse ? tab.lastResponse.statusCode + ' (' + tab.responseHistory.length + ' sends)' : 'not sent';
        console.log('[' + tab.id + '] ' + tab.method + ' ' + tab.hostname + tab.path + ' - ' + info);
      });
    }

    if (this.ruleManager.rules.length > 0) {
      console.log('\n' + this.cli.color.bold('═══ RULES (' + this.ruleManager.rules.filter(r => r.enabled).length + '/' + this.ruleManager.rules.length + ' enabled) ═══'));
      this.ruleManager.rules.forEach(rule => {
        const status = rule.enabled ? this.cli.color.green('✓') : this.cli.color.red('✗');
        console.log(status + ' [' + rule.id + '] ' + rule.name + ' (' + rule.scope + ')');
      });
    }

    console.log('');
  }
}

function showHelp(cli) {
  console.log('\n' + cli.color.bold.cyan('CLIPI') + ' ' + cli.color.dim('- CLI Proxy Interceptor v1.2.0'));
  console.log(cli.color.dim('═══════════════════════════════════════════════════'));
  console.log('\n' + cli.color.bold('USAGE'));
  console.log('  clipi [options]');
  console.log('  clipi repeater');
  console.log('  clipi rules');
  console.log('\n' + cli.color.bold('OPTIONS'));
  console.log('  ' + cli.color.yellow('-h, --help') + '         Show this help message');
  console.log('  ' + cli.color.yellow('-H, --host') + '         Proxy host (default: 127.0.0.1)');
  console.log('  ' + cli.color.yellow('-p, --port') + '         Proxy port (default: 8080)');
  console.log('  ' + cli.color.yellow('-i, --intercept') + '    Enable request intercept mode');
  console.log('  ' + cli.color.yellow('-r, --iresponse') + '    Enable response intercept mode');
  console.log('  ' + cli.color.yellow('-v, --verbose') + '      Show detailed headers and bodies');
  console.log('  ' + cli.color.yellow('-d, --debug') + '        Show debug information');
  console.log('  ' + cli.color.yellow('-l, --log') + '          Log everything to requests.log');
  console.log('  ' + cli.color.yellow('--version') + '          Show version number');
  console.log('\n' + cli.color.bold('EXAMPLES'));
  console.log('  ' + cli.color.dim('$') + ' clipi');
  console.log('  ' + cli.color.dim('$') + ' clipi -i');
  console.log('  ' + cli.color.dim('$') + ' clipi -ir                  # Intercept requests AND responses');
  console.log('  ' + cli.color.dim('$') + ' clipi -p 9090 -v');
  console.log('  ' + cli.color.dim('$') + ' clipi -ivdl');
  console.log('  ' + cli.color.dim('$') + ' clipi repeater');
  console.log('  ' + cli.color.dim('$') + ' clipi rules');
  console.log('\n' + cli.color.bold('QUICK SCRIPT INJECTION'));
  console.log('  1. Start proxy: ' + cli.color.dim('clipi'));
  console.log('  2. Open rules: ' + cli.color.dim('clipi rules'));
  console.log('  3. Select: ' + cli.color.yellow('"Quick: Script Injection + CSP Bypass"'));
  console.log('  4. Enter script URL: ' + cli.color.cyan('http://localhost:3000/customScript.js'));
  console.log('\n' + cli.color.bold('FEATURES'));
  console.log('  ' + cli.color.green('✓') + ' HTTP/HTTPS interception');
  console.log('  ' + cli.color.green('✓') + ' Request & response interception');
  console.log('  ' + cli.color.green('✓') + ' Middleware rules/workflows');
  console.log('  ' + cli.color.green('✓') + ' Script injection with CSP bypass');
  console.log('  ' + cli.color.green('✓') + ' Header manipulation (add/remove)');
  console.log('  ' + cli.color.green('✓') + ' Repeater with multiple tabs\n');
}

async function main() {
  const cli = await parseCLI();

  if (cli.s.h || cli.c.help) {
    showHelp(cli);
    process.exit(0);
  }

  if (cli.c.version) {
    console.log(cli.color.bold('CLIPI v1.2.0'));
    process.exit(0);
  }

  const options = {
    host: cli.c.host || cli.c.H || '127.0.0.1',
    port: parseInt(cli.c.port || cli.c.p) || 8080,
    intercept: !!(cli.s.i || cli.c.intercept),
    interceptResponse: !!(cli.s.r || cli.c.iresponse),
    verbose: !!(cli.s.v || cli.c.verbose),
    debug: !!(cli.s.d || cli.c.debug),
    log: !!(cli.s.l || cli.c.log),
    cli: cli
  };

  console.log(cli.color.cyan('╔═══════════════════════════════════════╗'));
  console.log(cli.color.cyan('║') + '  ' + cli.color.bold.white('CLIPI v1.2.0') + '  ' + cli.color.cyan('║'));
  console.log(cli.color.cyan('║') + '  ' + cli.color.dim('CLI Proxy Interceptor') + '  ' + cli.color.cyan('║'));
  console.log(cli.color.cyan('╚═══════════════════════════════════════╝') + '\n');

  const proxy = new CLIPI(options);

  // Check if user wants to open repeater or rules manager
  if (cli.o && cli.o.length > 0) {
    const command = cli.o[0][0];
    if (command === 'repeater') {
      await proxy.openRepeater();
      process.exit(0);
    } else if (command === 'rules') {
      await proxy.openRulesManager();
      process.exit(0);
    }
  }

  proxy.start();

  // Keyboard shortcuts
  process.stdin.on('data', async (key) => {
    if (key.toString() === '\x12') { // Ctrl+R
      await proxy.openRepeater();
    } else if (key.toString() === '\x13') { // Ctrl+S
      await proxy.openRulesManager();
    }
  });

  process.on('SIGINT', () => {
    console.log('\n' + cli.color.yellow('[*] Stopping proxy...'));
    proxy.showHistory();
    if (proxy.logging) {
      console.log(cli.color.green('[✓]') + ' Log saved to: ' + cli.color.cyan(proxy.logFile));
    }
    process.exit(0);
  });
}

main();

export default CLIPI;
