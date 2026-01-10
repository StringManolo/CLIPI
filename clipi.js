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
    this.ca = this.loadOrCreateCA();
    this.repeaterTabs = this.loadRepeaterTabs();
    this.repeaterCount = this.repeaterTabs.length > 0 ? 
      Math.max(...this.repeaterTabs.map(t => t.id)) : 0;
    
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
      console.log(this.cli.color.cyan('[*]') + ' Intercept mode: ' + (this.interceptMode ? this.cli.color.yellow('ACTIVE') : this.cli.color.dim('PASSIVE')));
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

    console.log(this.cli.color.bold('[' + reqId + ']') + ' ' + clientReq.method + ' ' + this.cli.color.blue(hostname + path) + ' ' + (isHttps ? this.cli.color.magenta('[HTTPS]') : ''));

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

    if (this.interceptMode) {
      const result = await this.interceptRequest(clientReq, requestBody, hostname, path, port, isHttps);

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

    const proxyReq = makeRequest(options, (proxyRes) => {
      const chunks = [];
      proxyRes.on('data', chunk => {
        chunks.push(chunk);
      });

      proxyRes.on('end', () => {
        const statusColor = proxyRes.statusCode < 300 ? this.cli.color.green :
                           proxyRes.statusCode < 400 ? this.cli.color.yellow : this.cli.color.red;
        console.log('    ' + statusColor('← ' + proxyRes.statusCode) + ' ' + http.STATUS_CODES[proxyRes.statusCode]);

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

        if (this.verbose || this.debug || this.logging) {
          let responseBody = Buffer.concat(chunks);
          
          if (this.debug) {
            console.log('  ' + this.cli.color.cyan('[DEBUG] Response:'), responseBody.length, 'bytes');
            console.log('  ' + this.cli.color.cyan('[DEBUG] Content-Encoding:'), proxyRes.headers['content-encoding'] || 'none');
          }

          const encoding = proxyRes.headers['content-encoding'];
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

          const bodyString = responseBody.toString('utf-8');
          
          if (this.debug) {
            console.log('  ' + this.cli.color.cyan('[DEBUG] Decompressed size:'), bodyString.length, 'chars');
          }

          if (this.logging) {
            this.log('[RESPONSE #' + reqId + '] ' + proxyRes.statusCode + ' ' + http.STATUS_CODES[proxyRes.statusCode]);
            this.log('Headers: ' + JSON.stringify(proxyRes.headers, null, 2));
            this.log('Body: ' + bodyString);
            this.log('─'.repeat(80));
          }

          if (this.verbose || this.debug) {
            console.log('  ' + this.cli.color.cyan('Response Headers:'), proxyRes.headers);
            console.log('  ' + this.cli.color.cyan('Response Body:'));
            const displayLimit = 1000;
            if (bodyString.length > displayLimit) {
              console.log(bodyString.substring(0, displayLimit));
              console.log('\n  ' + this.cli.color.yellow('... (' + (bodyString.length - displayLimit) + ' more chars - see requests.log for full body)'));
            } else {
              console.log(bodyString);
            }
          }
        }
      });

      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(clientRes);
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

  openEditor(content) {
    const editor = process.env.EDITOR || process.env.VISUAL || 'vim';
    const tmpFile = join(tmpdir(), 'clipi-request-' + Date.now() + '.txt');

    try {
      writeFileSync(tmpFile, content);

      const result = spawnSync(editor, [tmpFile], {
        stdio: 'inherit',
        shell: true
      });

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
      } catch {}
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
      console.log(this.cli.color.cyan('[🔄] Request sent to Repeater') + ' ' + this.cli.color.dim('(Tab ' + tab.id + ')') + '\n');
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

  createRepeaterTab(request) {
    this.repeaterCount++;
    const tab = new RepeaterTab(this.repeaterCount, request, this.debug);
    this.repeaterTabs.push(tab);
    this.saveRepeaterTabs();
    return tab;
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
      console.log(this.cli.color.cyan('║') + '      ' + this.cli.color.bold.white('CLIPI REPEATER') + '                   ' + this.cli.color.cyan('║'));
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

  async repeaterTabMenu(tab) {
    while (true) {
      console.clear();
      console.log(this.cli.color.magenta('╔═══ REPEATER TAB') + ' ' + this.cli.color.bold('#' + tab.id) + ' ' + this.cli.color.magenta('═══╗'));
      console.log(this.cli.color.magenta('║') + ' ' + tab.method + ' ' + this.cli.color.cyan(tab.hostname + tab.path));
      console.log(this.cli.color.magenta('║') + ' ' + this.cli.color.dim('Follow Redirects: ' + (tab.followRedirects ? 'ON' : 'OFF')));
      console.log(this.cli.color.magenta('╚═══════════════════════════╝') + '\n');

      if (tab.lastResponse) {
        const statusColor = tab.lastResponse.statusCode < 300 ? this.cli.color.green :
                           tab.lastResponse.statusCode < 400 ? this.cli.color.yellow : 
                           this.cli.color.red;
        console.log(this.cli.color.bold('Last Response:') + ' ' + statusColor(tab.lastResponse.statusCode) + ' ' + tab.lastResponse.statusMessage);
        console.log(this.cli.color.dim('Response Time: ' + tab.lastResponse.responseTime + 'ms'));
        console.log(this.cli.color.dim('Sent: ' + tab.responseHistory.length + ' times') + '\n');
      } else {
        console.log(this.cli.color.dim('No response yet - request not sent') + '\n');
      }

      const action = await prompts({
        type: 'select',
        name: 'value',
        message: 'Choose action:',
        choices: [
          { title: '🚀 Send', description: 'Send this request', value: 'send' },
          { title: '📄 View Request', description: 'Preview raw HTTP request', value: 'viewreq' },
          { title: '✎ Edit', description: 'Modify request', value: 'edit' },
          { title: '👁 View Response', description: 'View last response body', value: 'view', disabled: !tab.lastResponse },
          { title: '📊 Headers', description: 'View response headers', value: 'headers', disabled: !tab.lastResponse },
          { title: '🔍 Search', description: 'Search in response body', value: 'search', disabled: !tab.lastResponse },
          { title: '⚖️ Compare', description: 'Compare two responses', value: 'compare', disabled: tab.responseHistory.length < 2 },
          { title: '📜 History', description: 'View all responses', value: 'history', disabled: tab.responseHistory.length === 0 },
          { title: '📋 Copy as cURL', description: 'Copy request as cURL command', value: 'curl' },
          { title: '⚙️ Settings', description: 'Toggle follow redirects', value: 'settings' },
          { title: '💾 Save', description: 'Save request to file', value: 'save' },
          { title: '📂 Load', description: 'Load request from file', value: 'load' },
          { title: '🗑 Delete Tab', description: 'Remove this repeater tab', value: 'delete' },
          { title: '← Back', description: 'Return to tab list', value: 'back' }
        ]
      });

      if (!action.value || action.value === 'back') {
        return;
      }

      switch (action.value) {
        case 'send':
          await this.sendRepeaterRequest(tab);
          break;
        case 'viewreq':
          await this.viewRequest(tab);
          break;
        case 'edit':
          await this.editRepeaterRequest(tab);
          break;
        case 'view':
          await this.viewResponse(tab);
          break;
        case 'headers':
          await this.viewResponseHeaders(tab);
          break;
        case 'search':
          await this.searchInResponse(tab);
          break;
        case 'compare':
          await this.compareResponses(tab);
          break;
        case 'history':
          await this.viewResponseHistory(tab);
          break;
        case 'curl':
          await this.copyAsCurl(tab);
          break;
        case 'settings':
          await this.toggleSettings(tab);
          break;
        case 'save':
          await this.saveRepeaterRequest(tab);
          break;
        case 'load':
          await this.loadRepeaterRequest(tab);
          break;
        case 'delete':
          const confirm = await prompts({
            type: 'confirm',
            name: 'value',
            message: 'Delete this repeater tab?',
            initial: false
          });
          if (confirm.value) {
            this.repeaterTabs = this.repeaterTabs.filter(t => t.id !== tab.id);
            this.saveRepeaterTabs();
            console.log(this.cli.color.green('[✓]') + ' Tab deleted\n');
            return;
          }
          break;
      }
    }
  }

  async sendRepeaterRequest(tab) {
    console.log('\n' + this.cli.color.cyan('[→]') + ' Sending request...');
    
    if (this.logging) {
      this.log('\n[REPEATER #' + tab.id + '] Sending request');
      this.log('URL: ' + (tab.isHttps ? 'https' : 'http') + '://' + tab.hostname + ':' + tab.port + tab.path);
      this.log('Method: ' + tab.method);
      this.log('Headers: ' + JSON.stringify(tab.headers, null, 2));
      if (tab.body) {
        this.log('Body: ' + tab.body);
      }
    }
    
    try {
      const response = await tab.send();
      this.saveRepeaterTabs();
      
      if (this.logging) {
        this.log('[REPEATER #' + tab.id + '] Response: ' + response.statusCode + ' ' + response.statusMessage + ' (' + response.responseTime + 'ms)');
        this.log('Headers: ' + JSON.stringify(response.headers, null, 2));
        this.log('Body: ' + response.body);
        this.log('─'.repeat(80));
      }
      
      const statusColor = response.statusCode < 300 ? this.cli.color.green :
                         response.statusCode < 400 ? this.cli.color.yellow :
                         this.cli.color.red;
      console.log(statusColor('[✓]') + ' ' + response.statusCode + ' ' + response.statusMessage + ' ' + this.cli.color.dim('(' + response.responseTime + 'ms)'));
      await this.pause();
    } catch (err) {
      if (this.logging) {
        this.log('[REPEATER #' + tab.id + '] Error: ' + err.message);
      }
      console.log(this.cli.color.red('[✗]') + ' Error: ' + err.message);
      await this.pause();
    }
  }

  async editRepeaterRequest(tab) {
    const raw = tab.serializeRequest();
    const modified = this.openEditor(raw);
    
    if (modified) {
      try {
        tab.updateFromRaw(modified);
        this.saveRepeaterTabs();
        console.log(this.cli.color.green('[✓]') + ' Request updated');
      } catch (err) {
        console.log(this.cli.color.red('[✗]') + ' Invalid format: ' + err.message);
      }
      await this.pause();
    }
  }

  async viewRequest(tab) {
    console.clear();
    console.log(this.cli.color.magenta('═══ RAW HTTP REQUEST ═══') + '\n');
    
    const raw = tab.serializeRequest();
    console.log(raw);
    
    await this.pause();
  }

  async viewResponse(tab) {
    if (!tab.lastResponse) return;
    
    console.clear();
    console.log(this.cli.color.magenta('═══ RESPONSE BODY ═══') + '\n');
    
    const body = tab.lastResponse.body;
    if (!body || body.trim() === '') {
      console.log(this.cli.color.dim('(empty response body)'));
      await this.pause();
      return;
    }
    
    const limit = 5000;
    const isTruncated = body.length > limit;
    
    if (isTruncated) {
      console.log(body.substring(0, limit));
      console.log('\n' + this.cli.color.yellow('... (showing ' + limit + ' of ' + body.length + ' chars)'));
      
      const showAll = await prompts({
        type: 'confirm',
        name: 'value',
        message: 'Show full body? (' + body.length + ' chars)',
        initial: false
      });
      
      if (showAll.value) {
        console.clear();
        console.log(this.cli.color.magenta('═══ FULL RESPONSE BODY ═══') + '\n');
        console.log(body);
      }
    } else {
      console.log(body);
    }
    
    await this.pause();
  }

  async viewResponseHeaders(tab) {
    if (!tab.lastResponse) return;
    
    console.clear();
    console.log(this.cli.color.magenta('═══ RESPONSE HEADERS ═══') + '\n');
    console.log('Status: ' + tab.lastResponse.statusCode + ' ' + tab.lastResponse.statusMessage);
    console.log('Time: ' + tab.lastResponse.responseTime + 'ms\n');
    Object.entries(tab.lastResponse.headers).forEach(([key, value]) => {
      console.log(this.cli.color.cyan(key) + ': ' + value);
    });
    console.log('\n' + this.cli.color.dim('Press Enter to continue...'));
    await prompts({
      type: 'text',
      name: 'continue',
      message: ''
    });
  }

  async copyAsCurl(tab) {
    const curlCmd = this.generateCurl(tab);
    
    console.clear();
    console.log(this.cli.color.magenta('═══ cURL COMMAND ═══') + '\n');
    console.log(curlCmd);
    console.log('\n' + this.cli.color.dim('Copy the command above'));
    
    const exportOptions = await prompts({
      type: 'select',
      name: 'value',
      message: 'Export to file?',
      choices: [
        { title: '💾 Save to file', value: 'save' },
        { title: '← Back', value: 'back' }
      ]
    });
    
    if (exportOptions.value === 'save') {
      const filename = await prompts({
        type: 'text',
        name: 'value',
        message: 'Filename:',
        initial: 'curl-' + tab.id + '.sh'
      });
      
      if (filename.value) {
        try {
          writeFileSync(filename.value, curlCmd);
          chmodSync(filename.value, 0o775);
          console.log(this.cli.color.green('[✓]') + ' Saved to ' + filename.value + ' (permissions: 775)');
          await this.pause();
        } catch (err) {
          console.log(this.cli.color.red('[✗]') + ' Error: ' + err.message);
          await this.pause();
        }
      }
    }
  }

  generateCurl(tab) {
    const protocol = tab.isHttps ? 'https' : 'http';
    const url = protocol + '://' + tab.hostname + ':' + tab.port + tab.path;
    
    let curl = '#!/bin/bash\n# Generated by CLIPI\n\n';
    curl += 'curl -X ' + tab.method + " '" + url + "'";
    
    Object.entries(tab.headers).forEach(([key, value]) => {
      if (key.toLowerCase() !== 'host') {
        curl += " \\\n  -H '" + key + ': ' + value + "'";
      }
    });
    
    if (tab.body) {
      const escapedBody = tab.body.replace(/'/g, "'\\''");
      curl += " \\\n  -d '" + escapedBody + "'";
    }
    
    if (!tab.followRedirects) {
      curl += ' \\\n  --max-redirs 0';
    }
    
    return curl;
  }

  async toggleSettings(tab) {
    console.clear();
    console.log(this.cli.color.magenta('═══ SETTINGS ═══') + '\n');
    
    const setting = await prompts({
      type: 'select',
      name: 'value',
      message: 'Configure:',
      choices: [
        { 
          title: 'Follow Redirects: ' + (tab.followRedirects ? this.cli.color.green('ON') : this.cli.color.red('OFF')),
          description: 'Toggle automatic redirect following',
          value: 'redirects'
        },
        { title: '← Back', value: 'back' }
      ]
    });
    
    if (setting.value === 'redirects') {
      tab.followRedirects = !tab.followRedirects;
      this.saveRepeaterTabs();
      console.log(this.cli.color.green('[✓]') + ' Follow Redirects: ' + (tab.followRedirects ? 'ON' : 'OFF'));
      await this.pause();
    }
  }

  async saveRepeaterRequest(tab) {
    const filename = await prompts({
      type: 'text',
      name: 'value',
      message: 'Filename:',
      initial: 'repeater-' + tab.id + '.txt'
    });

    if (filename.value) {
      try {
        writeFileSync(filename.value, tab.serializeRequest());
        console.log(this.cli.color.green('[✓]') + ' Saved to ' + filename.value);
      } catch (err) {
        console.log(this.cli.color.red('[✗]') + ' Error: ' + err.message);
      }
      await this.pause();
    }
  }

  async loadRepeaterRequest(tab) {
    const filename = await prompts({
      type: 'text',
      name: 'value',
      message: 'Filename:',
      initial: 'request.txt'
    });

    if (filename.value) {
      try {
        const raw = readFileSync(filename.value, 'utf-8');
        tab.updateFromRaw(raw);
        this.saveRepeaterTabs();
        console.log(this.cli.color.green('[✓]') + ' Request loaded from ' + filename.value);
      } catch (err) {
        console.log(this.cli.color.red('[✗]') + ' Error: ' + err.message);
      }
      await this.pause();
    }
  }

  async pause() {
    console.log('\n' + this.cli.color.dim('Press Enter to continue...'));
    await prompts({
      type: 'text',
      name: 'continue',
      message: ''
    });
  }

  async searchInResponse(tab) {
    if (!tab.lastResponse) return;

    const searchQuery = await prompts({
      type: 'text',
      name: 'value',
      message: 'Search for:',
      validate: value => value.length > 0 || 'Please enter a search term'
    });

    if (!searchQuery.value) return;

    console.clear();
    console.log(this.cli.color.magenta('═══ SEARCH RESULTS ═══') + '\n');
    console.log(this.cli.color.cyan('Query:') + ' ' + searchQuery.value + '\n');

    const body = tab.lastResponse.body;
    const lines = body.split('\n');
    let matches = 0;

    lines.forEach((line, index) => {
      if (line.toLowerCase().includes(searchQuery.value.toLowerCase())) {
        matches++;
        const highlighted = line.replace(
          new RegExp(searchQuery.value, 'gi'),
          match => this.cli.color.yellow.bold(match)
        );
        console.log(this.cli.color.dim('Line ' + (index + 1) + ':') + ' ' + highlighted);
      }
    });

    if (matches === 0) {
      console.log(this.cli.color.red('No matches found'));
    } else {
      console.log('\n' + this.cli.color.green('Found ' + matches + ' match' + (matches > 1 ? 'es' : '')));
    }

    await this.pause();
  }

  async viewResponseHistory(tab) {
    if (tab.responseHistory.length === 0) return;

    console.clear();
    console.log(this.cli.color.magenta('═══ RESPONSE HISTORY ═══') + '\n');

    const choices = tab.responseHistory.map((resp, index) => {
      const statusColor = resp.statusCode < 300 ? this.cli.color.green :
                         resp.statusCode < 400 ? this.cli.color.yellow :
                         this.cli.color.red;
      return {
        title: '#' + (index + 1) + ' - ' + statusColor(resp.statusCode) + ' ' + resp.statusMessage + ' (' + resp.responseTime + 'ms)',
        description: new Date(resp.timestamp).toLocaleTimeString(),
        value: index
      };
    });

    choices.push({ title: '← Back', value: 'back' });

    const selection = await prompts({
      type: 'select',
      name: 'value',
      message: 'Select response to view:',
      choices: choices
    });

    if (selection.value === 'back' || selection.value === undefined) return;

    const selectedResp = tab.responseHistory[selection.value];
    
    console.clear();
    console.log(this.cli.color.magenta('═══ RESPONSE #' + (selection.value + 1) + ' ═══') + '\n');
    console.log(this.cli.color.cyan('Status:') + ' ' + selectedResp.statusCode + ' ' + selectedResp.statusMessage);
    console.log(this.cli.color.cyan('Time:') + ' ' + selectedResp.responseTime + 'ms');
    console.log(this.cli.color.cyan('Timestamp:') + ' ' + selectedResp.timestamp + '\n');
    console.log(this.cli.color.cyan('Headers:'));
    Object.entries(selectedResp.headers).forEach(([key, value]) => {
      console.log('  ' + this.cli.color.dim(key) + ': ' + value);
    });
    console.log('\n' + this.cli.color.cyan('Body:'));
    const display = selectedResp.body.length > 3000 ? 
      selectedResp.body.substring(0, 3000) + '\n\n' + this.cli.color.yellow('... (' + (selectedResp.body.length - 3000) + ' more chars)') : 
      selectedResp.body;
    console.log(display);

    await this.pause();
  }

  async compareResponses(tab) {
    if (tab.responseHistory.length < 2) return;

    console.clear();
    console.log(this.cli.color.magenta('═══ COMPARE RESPONSES ═══') + '\n');

    const choices = tab.responseHistory.map((resp, index) => {
      const statusColor = resp.statusCode < 300 ? this.cli.color.green :
                         resp.statusCode < 400 ? this.cli.color.yellow :
                         this.cli.color.red;
      return {
        title: '#' + (index + 1) + ' - ' + statusColor(resp.statusCode) + ' ' + resp.statusMessage + ' (' + resp.responseTime + 'ms)',
        description: new Date(resp.timestamp).toLocaleTimeString(),
        value: index
      };
    });

    const first = await prompts({
      type: 'select',
      name: 'value',
      message: 'Select FIRST response:',
      choices: choices
    });

    if (first.value === undefined) return;

    const second = await prompts({
      type: 'select',
      name: 'value',
      message: 'Select SECOND response:',
      choices: choices.filter((_, idx) => idx !== first.value)
    });

    if (second.value === undefined) return;

    const resp1 = tab.responseHistory[first.value];
    const resp2 = tab.responseHistory[second.value];

    console.clear();
    console.log(this.cli.color.magenta('═══ RESPONSE COMPARISON ═══') + '\n');
    
    console.log(this.cli.color.bold('Response #' + (first.value + 1)) + ' vs ' + this.cli.color.bold('Response #' + (second.value + 1)) + '\n');

    console.log(this.cli.color.cyan('Status Code:'));
    if (resp1.statusCode !== resp2.statusCode) {
      console.log('  ' + this.cli.color.red('✗') + ' ' + resp1.statusCode + ' → ' + resp2.statusCode + ' ' + this.cli.color.yellow('(DIFFERENT)'));
    } else {
      console.log('  ' + this.cli.color.green('✓') + ' ' + resp1.statusCode + ' (same)');
    }

    console.log('\n' + this.cli.color.cyan('Response Time:'));
    const timeDiff = Math.abs(resp1.responseTime - resp2.responseTime);
    if (timeDiff > 50) {
      console.log('  ' + this.cli.color.yellow('⚠') + ' ' + resp1.responseTime + 'ms vs ' + resp2.responseTime + 'ms ' + this.cli.color.yellow('(diff: ' + timeDiff + 'ms)'));
    } else {
      console.log('  ' + this.cli.color.green('✓') + ' ' + resp1.responseTime + 'ms vs ' + resp2.responseTime + 'ms (similar)');
    }

    console.log('\n' + this.cli.color.cyan('Content Length:'));
    if (resp1.body.length !== resp2.body.length) {
      console.log('  ' + this.cli.color.red('✗') + ' ' + resp1.body.length + ' → ' + resp2.body.length + ' chars ' + this.cli.color.yellow('(diff: ' + Math.abs(resp1.body.length - resp2.body.length) + ')'));
    } else {
      console.log('  ' + this.cli.color.green('✓') + ' ' + resp1.body.length + ' chars (same)');
    }

    console.log('\n' + this.cli.color.cyan('Headers Diff:'));
    const headers1 = Object.keys(resp1.headers);
    const headers2 = Object.keys(resp2.headers);
    const allHeaders = new Set([...headers1, ...headers2]);
    
    let headerDiffs = 0;
    allHeaders.forEach(header => {
      const val1 = resp1.headers[header];
      const val2 = resp2.headers[header];
      
      if (val1 !== val2) {
        headerDiffs++;
        if (!val1) {
          console.log('  ' + this.cli.color.green('+') + ' ' + header + ': ' + val2);
        } else if (!val2) {
          console.log('  ' + this.cli.color.red('-') + ' ' + header + ': ' + val1);
        } else {
          console.log('  ' + this.cli.color.yellow('~') + ' ' + header + ':');
          console.log('    ' + this.cli.color.red('-') + ' ' + val1);
          console.log('    ' + this.cli.color.green('+') + ' ' + val2);
        }
      }
    });

    if (headerDiffs === 0) {
      console.log('  ' + this.cli.color.green('✓') + ' Headers are identical');
    } else {
      console.log('  ' + this.cli.color.yellow('Found ' + headerDiffs + ' difference(s)'));
    }

    console.log('\n' + this.cli.color.cyan('Body Diff:'));
    
    if (resp1.body === resp2.body) {
      console.log('  ' + this.cli.color.green('✓') + ' Bodies are identical');
    } else {
      const lines1 = resp1.body.split('\n');
      const lines2 = resp2.body.split('\n');
      const maxLines = Math.max(lines1.length, lines2.length);
      
      let diffCount = 0;
      let shownDiffs = 0;
      const maxDiffsToShow = 20;

      for (let i = 0; i < maxLines && shownDiffs < maxDiffsToShow; i++) {
        const line1 = lines1[i] || '';
        const line2 = lines2[i] || '';
        
        if (line1 !== line2) {
          diffCount++;
          if (shownDiffs < maxDiffsToShow) {
            console.log('  ' + this.cli.color.dim('Line ' + (i + 1) + ':'));
            if (line1) console.log('    ' + this.cli.color.red('-') + ' ' + line1.substring(0, 100));
            if (line2) console.log('    ' + this.cli.color.green('+') + ' ' + line2.substring(0, 100));
            shownDiffs++;
          }
        }
      }

      if (diffCount > maxDiffsToShow) {
        console.log('\n  ' + this.cli.color.yellow('... and ' + (diffCount - maxDiffsToShow) + ' more differences'));
      }

      console.log('\n  ' + this.cli.color.yellow('Total: ' + diffCount + ' line(s) differ'));
    }

    await this.pause();
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
        const info = tab.lastResponse ? 
          tab.lastResponse.statusCode + ' (' + tab.responseHistory.length + ' sends)' : 
          'not sent';
        console.log('[' + tab.id + '] ' + tab.method + ' ' + tab.hostname + tab.path + ' - ' + info);
      });
    }
    console.log('');
  }
}

function showHelp(cli) {
  console.log('\n' + cli.color.bold.cyan('CLIPI') + ' ' + cli.color.dim('- CLI Proxy Interceptor v1.1.0'));
  console.log(cli.color.dim('═══════════════════════════════════════════════════'));
  console.log('\n' + cli.color.bold('USAGE'));
  console.log('  clipi [options]');
  console.log('  clipi repeater');
  console.log('\n' + cli.color.bold('OPTIONS'));
  console.log('  ' + cli.color.yellow('-h, --help') + '        Show this help message');
  console.log('  ' + cli.color.yellow('-H, --host') + '        Proxy host (default: 127.0.0.1)');
  console.log('  ' + cli.color.yellow('-p, --port') + '        Proxy port (default: 8080)');
  console.log('  ' + cli.color.yellow('-i, --intercept') + '   Enable manual intercept mode');
  console.log('  ' + cli.color.yellow('-v, --verbose') + '     Show detailed headers and bodies');
  console.log('  ' + cli.color.yellow('-d, --debug') + '       Show debug information');
  console.log('  ' + cli.color.yellow('-l, --log') + '         Log everything to requests.log');
  console.log('  ' + cli.color.yellow('--version') + '         Show version number');
  console.log('\n' + cli.color.bold('EXAMPLES'));
  console.log('  ' + cli.color.dim('$') + ' clipi');
  console.log('  ' + cli.color.dim('$') + ' clipi -i');
  console.log('  ' + cli.color.dim('$') + ' clipi -p 9090 -v');
  console.log('  ' + cli.color.dim('$') + ' clipi -ivdl');
  console.log('  ' + cli.color.dim('$') + ' clipi repeater');
  console.log('\n' + cli.color.bold('PROXY CONFIGURATION'));
  console.log('  Configure your browser or application:');
  console.log('    Host: 127.0.0.1');
  console.log('    Port: 8080');
  console.log('\n' + cli.color.bold('FEATURES'));
  console.log('  ' + cli.color.green('✓') + ' HTTP/HTTPS interception');
  console.log('  ' + cli.color.green('✓') + ' Request forwarding and blocking');
  console.log('  ' + cli.color.green('✓') + ' Request modification with editor');
  console.log('  ' + cli.color.green('✓') + ' Repeater with multiple tabs');
  console.log('  ' + cli.color.green('✓') + ' Response comparison and search');
  console.log('  ' + cli.color.green('✓') + ' Copy as cURL command');
  console.log('  ' + cli.color.green('✓') + ' Complete request/response logging');
  console.log('  ' + cli.color.green('✓') + ' Verbose mode for debugging\n');
}

async function main() {
  const cli = await parseCLI();

  if (cli.s.h || cli.c.help) {
    showHelp(cli);
    process.exit(0);
  }

  if (cli.c.version) {
    console.log(cli.color.bold('CLIPI v1.1.0'));
    process.exit(0);
  }

  const options = {
    host: cli.c.host || cli.c.H || '127.0.0.1',
    port: parseInt(cli.c.port || cli.c.p) || 8080,
    intercept: !!(cli.s.i || cli.c.intercept),
    verbose: !!(cli.s.v || cli.c.verbose),
    debug: !!(cli.s.d || cli.c.debug),
    log: !!(cli.s.l || cli.c.log),
    cli: cli
  };

  console.log(cli.color.cyan('╔═══════════════════════════════════════╗'));
  console.log(cli.color.cyan('║') + '      ' + cli.color.bold.white('CLIPI v1.1.0') + '                     ' + cli.color.cyan('║'));
  console.log(cli.color.cyan('║') + '  ' + cli.color.dim('CLI Proxy Interceptor') + '                ' + cli.color.cyan('║'));
  console.log(cli.color.cyan('╚═══════════════════════════════════════╝') + '\n');

  const proxy = new CLIPI(options);

  if (cli.o && cli.o.some(arg => arg[0] === 'repeater')) {
    await proxy.openRepeater();
    process.exit(0);
  }

  proxy.start();

  process.stdin.on('data', async (key) => {
    if (key.toString() === '\x12') {
      await proxy.openRepeater();
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