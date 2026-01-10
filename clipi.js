#!/usr/bin/env node

import http from 'http';
import https from 'https';
import net from 'net';
import { parse as parseUrl } from 'url';
import prompts from 'prompts';
import { writeFileSync, readFileSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { tmpdir, homedir } from 'os';
import { spawnSync } from 'child_process';
import { join } from 'path';
import forge from 'node-forge';
import parseCLI from 'simpleargumentsparser';

class RepeaterTab {
  constructor(id, request) {
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
  }

  serializeRequest() {
    let raw = `${this.method} ${this.path} HTTP/1.1\r\n`;
    raw += `Host: ${this.hostname}\r\n`;
    
    Object.entries(this.headers).forEach(([key, value]) => {
      if (key.toLowerCase() !== 'host') {
        raw += `${key}: ${value}\r\n`;
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
        headers: { ...this.headers, host: this.hostname }
      };

      const makeRequest = this.isHttps ? https.request : http.request;
      const startTime = Date.now();

      const req = makeRequest(options, (res) => {
        let responseBody = '';
        res.on('data', chunk => {
          responseBody += chunk.toString();
        });

        res.on('end', () => {
          const responseTime = Date.now() - startTime;
          const response = {
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            body: responseBody,
            responseTime,
            timestamp: new Date().toISOString()
          };
          
          this.lastResponse = response;
          this.responseHistory.push(response);
          resolve(response);
        });
      });

      req.on('error', (err) => {
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
    this.requestCount = 0;
    this.history = [];
    this.cli = options.cli;
    this.certCache = new Map();
    this.certDir = join(homedir(), '.clipi', 'certs');
    this.ca = this.loadOrCreateCA();
    this.repeaterTabs = [];
    this.repeaterCount = 0;
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

    console.log(`${this.cli.color.yellow('[*]')} Generating CA certificate...`);

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

    console.log(`${this.cli.color.green('[✓]')} CA certificate created at: ${this.cli.color.cyan(this.certDir)}`);
    console.log(`${this.cli.color.yellow('[!]')} Install ca-cert.pem on your device to intercept HTTPS`);

    return { key: pemKey, cert: pemCert };
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
      console.log(`${this.cli.color.green('[+]')} CLIPI started on ${this.cli.color.bold(`${this.host}:${this.port}`)}`);
      console.log(`${this.cli.color.cyan('[*]')} Intercept mode: ${this.interceptMode ? this.cli.color.yellow('ACTIVE') : this.cli.color.dim('PASSIVE')}`);
      console.log(`${this.cli.color.yellow('[*]')} Press Ctrl+C to stop\n`);
    });

    server.on('error', (err) => {
      console.error(`${this.cli.color.red('[ERROR]')} ${err.message}`);
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

    console.log(`${this.cli.color.bold(`[${reqId}]`)} ${clientReq.method} ${this.cli.color.blue(`${hostname}${path}`)} ${isHttps ? this.cli.color.magenta('[HTTPS]') : ''}`);

    let requestBody = '';
    clientReq.on('data', chunk => {
      requestBody += chunk.toString();
    });

    await new Promise(resolve => clientReq.on('end', resolve));

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
        clientRes.writeHead(403);
        clientRes.end('Request blocked by proxy');
        return;
      }

      // Repeater: save to repeater AND forward the request
      if (result.action === 'repeater') {
        // Request continues to be forwarded below
      }

      if (result.action === 'modify') {
        method = result.data.method;
        finalPath = result.data.path;
        headers = result.data.headers;
        body = result.data.body;
      }
    }

    if (this.verbose) {
      console.log(`  ${this.cli.color.cyan('Headers:')}`, headers);
      if (body) {
        console.log(`  ${this.cli.color.cyan('Body:')}`, body.substring(0, 200));
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
      let responseBody = '';
      proxyRes.on('data', chunk => {
        responseBody += chunk.toString();
      });

      proxyRes.on('end', () => {
        const statusColor = proxyRes.statusCode < 300 ? this.cli.color.green :
                           proxyRes.statusCode < 400 ? this.cli.color.yellow : this.cli.color.red;
        console.log(`    ${statusColor(`← ${proxyRes.statusCode}`)} ${http.STATUS_CODES[proxyRes.statusCode]}`);

        this.history.push({
          id: reqId,
          method: clientReq.method,
          url: `${hostname}${path}`,
          status: proxyRes.statusCode,
          requestHeaders: clientReq.headers,
          responseHeaders: proxyRes.headers,
          timestamp: new Date().toISOString(),
          https: isHttps
        });

        if (this.verbose) {
          console.log(`  ${this.cli.color.cyan('Response Headers:')}`, proxyRes.headers);
          console.log(`  ${this.cli.color.cyan('Response Body:')}`, responseBody.substring(0, 200));
        }
      });

      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(clientRes);
    });

    proxyReq.on('error', (err) => {
      console.error(`${this.cli.color.red('[!]')} Error connecting to ${hostname}: ${err.message}`);
      clientRes.writeHead(502);
      clientRes.end('Bad Gateway');
    });

    if (body) {
      proxyReq.write(body);
    }
    proxyReq.end();
  }

  handleHTTPS(req, clientSocket, head) {
    const { port, hostname } = parseUrl(`//${req.url}`, false, true);
    const targetPort = port || 443;

    console.log(`${this.cli.color.cyan('[HTTPS]')} CONNECT ${hostname}:${targetPort}`);

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const cert = this.generateCertificate(hostname);

    const httpsServer = https.createServer(
      { key: cert.key, cert: cert.cert },
      (req, res) => {
        this.handleHTTP(req, res, true, hostname, targetPort);
      }
    );

    httpsServer.once('error', (err) => {
      console.error(`${this.cli.color.red('[!]')} HTTPS server error: ${err.message}`);
      clientSocket.end();
    });

    httpsServer.emit('connection', clientSocket);

    if (head && head.length > 0) {
      clientSocket.unshift(head);
    }
  }

  serializeRequest(method, hostname, path, headers, body) {
    let raw = `${method} ${path} HTTP/1.1\r\n`;
    raw += `Host: ${hostname}\r\n`;

    Object.entries(headers).forEach(([key, value]) => {
      if (key.toLowerCase() !== 'host') {
        raw += `${key}: ${value}\r\n`;
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
    const tmpFile = join(tmpdir(), `clipi-request-${Date.now()}.txt`);

    try {
      writeFileSync(tmpFile, content);

      const result = spawnSync(editor, [tmpFile], {
        stdio: 'inherit',
        shell: true
      });

      if (result.error) {
        console.log(`${this.cli.color.red('[!]')} Error opening editor: ${result.error.message}`);
        return null;
      }

      const modified = readFileSync(tmpFile, 'utf-8');
      unlinkSync(tmpFile);

      return modified;
    } catch (err) {
      console.log(`${this.cli.color.red('[!]')} Error: ${err.message}`);
      try {
        unlinkSync(tmpFile);
      } catch {}
      return null;
    }
  }

  async interceptRequest(req, body, hostname, path, port, isHttps) {
    console.log(`\n${this.cli.color.yellow('╔═══ REQUEST INTERCEPTED ═══╗')}`);
    console.log(`${this.cli.color.yellow('║')} ${this.cli.color.bold('Method:')} ${req.method}`);
    console.log(`${this.cli.color.yellow('║')} ${this.cli.color.bold('URL:')} ${hostname}${path}`);
    
    if (this.verbose) {
      console.log(`${this.cli.color.yellow('║')} ${this.cli.color.bold('Headers:')}`);
      Object.entries(req.headers).forEach(([key, value]) => {
        console.log(`${this.cli.color.yellow('║')}   ${key}: ${value}`);
      });
      if (body) {
        console.log(`${this.cli.color.yellow('║')} ${this.cli.color.bold('Body:')}`);
        console.log(`${this.cli.color.yellow('║')}   ${body.substring(0, 200)}`);
      }
    }
    
    console.log(`${this.cli.color.yellow('╚═══════════════════════════╝')}\n`);

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
      console.log(`${this.cli.color.yellow('[!] Cancelled, forwarding request')}\n`);
      return { action: 'forward' };
    }

    if (response.action === 'drop') {
      console.log(`${this.cli.color.red('[✗] Request dropped')}\n`);
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
      console.log(`${this.cli.color.cyan('[🔄] Request sent to Repeater')} ${this.cli.color.dim(`(Tab ${tab.id})`)}\n`);
      return { action: 'repeater' };
    }

    if (response.action === 'modify') {
      const rawRequest = this.serializeRequest(req.method, hostname, path, req.headers, body);
      const modified = this.openEditor(rawRequest);

      if (modified) {
        try {
          const parsed = this.parseModifiedRequest(modified);
          console.log(`${this.cli.color.green('[✓] Request modified')}\n`);
          return { action: 'modify', data: parsed };
        } catch (err) {
          console.log(`${this.cli.color.red('[!] Invalid request format, forwarding original')}\n`);
          return { action: 'forward' };
        }
      } else {
        console.log(`${this.cli.color.yellow('[!] Editor closed, forwarding original')}\n`);
        return { action: 'forward' };
      }
    }

    console.log(`${this.cli.color.green('[→] Request forwarded')}\n`);
    return { action: 'forward' };
  }

  createRepeaterTab(request) {
    this.repeaterCount++;
    const tab = new RepeaterTab(this.repeaterCount, request);
    this.repeaterTabs.push(tab);
    return tab;
  }

  async openRepeater() {
    if (this.repeaterTabs.length === 0) {
      console.log(`${this.cli.color.yellow('[!]')} No repeater tabs available`);
      console.log(`${this.cli.color.dim('Intercept a request and send it to Repeater first')}\n`);
      return;
    }

    let currentTab = null;

    while (true) {
      console.clear();
      console.log(`${this.cli.color.cyan('╔═══════════════════════════════════════╗')}`);
      console.log(`${this.cli.color.cyan('║')}      ${this.cli.color.bold.white('CLIPI REPEATER')}                   ${this.cli.color.cyan('║')}`);
      console.log(`${this.cli.color.cyan('╚═══════════════════════════════════════╝')}\n`);

      const tabChoices = this.repeaterTabs.map(tab => ({
        title: `Tab ${tab.id}: ${tab.method} ${tab.hostname}${tab.path}`,
        description: tab.lastResponse ? `Last: ${tab.lastResponse.statusCode} (${tab.lastResponse.responseTime}ms)` : 'Not sent yet',
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
      console.log(`${this.cli.color.magenta('╔═══ REPEATER TAB')} ${this.cli.color.bold(`#${tab.id}`)} ${this.cli.color.magenta('═══╗')}`);
      console.log(`${this.cli.color.magenta('║')} ${tab.method} ${this.cli.color.cyan(`${tab.hostname}${tab.path}`)}`);
      console.log(`${this.cli.color.magenta('╚═══════════════════════════╝')}\n`);

      if (tab.lastResponse) {
        const statusColor = tab.lastResponse.statusCode < 300 ? this.cli.color.green :
                           tab.lastResponse.statusCode < 400 ? this.cli.color.yellow : 
                           this.cli.color.red;
        console.log(`${this.cli.color.bold('Last Response:')} ${statusColor(tab.lastResponse.statusCode)} ${tab.lastResponse.statusMessage}`);
        console.log(`${this.cli.color.dim(`Response Time: ${tab.lastResponse.responseTime}ms`)}`);
        console.log(`${this.cli.color.dim(`Sent: ${tab.responseHistory.length} times`)}\n`);
      } else {
        console.log(`${this.cli.color.dim('No response yet - request not sent')}\n`);
      }

      const action = await prompts({
        type: 'select',
        name: 'value',
        message: 'Choose action:',
        choices: [
          { title: '🚀 Send', description: 'Send this request', value: 'send' },
          { title: '✎ Edit', description: 'Modify request', value: 'edit' },
          { title: '👁 View Response', description: 'View last response body', value: 'view', disabled: !tab.lastResponse },
          { title: '📊 Headers', description: 'View response headers', value: 'headers', disabled: !tab.lastResponse },
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
        case 'edit':
          await this.editRepeaterRequest(tab);
          break;
        case 'view':
          await this.viewResponse(tab);
          break;
        case 'headers':
          await this.viewResponseHeaders(tab);
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
            console.log(`${this.cli.color.green('[✓]')} Tab deleted\n`);
            return;
          }
          break;
      }
    }
  }

  async sendRepeaterRequest(tab) {
    console.log(`\n${this.cli.color.cyan('[→]')} Sending request...`);
    try {
      const response = await tab.send();
      const statusColor = response.statusCode < 300 ? this.cli.color.green :
                         response.statusCode < 400 ? this.cli.color.yellow :
                         this.cli.color.red;
      console.log(`${statusColor('[✓]')} ${response.statusCode} ${response.statusMessage} ${this.cli.color.dim(`(${response.responseTime}ms)`)}`);
      await this.pause();
    } catch (err) {
      console.log(`${this.cli.color.red('[✗]')} Error: ${err.message}`);
      await this.pause();
    }
  }

  async editRepeaterRequest(tab) {
    const raw = tab.serializeRequest();
    const modified = this.openEditor(raw);
    
    if (modified) {
      try {
        tab.updateFromRaw(modified);
        console.log(`${this.cli.color.green('[✓]')} Request updated`);
      } catch (err) {
        console.log(`${this.cli.color.red('[✗]')} Invalid format: ${err.message}`);
      }
      await this.pause();
    }
  }

  async viewResponse(tab) {
    if (!tab.lastResponse) return;
    
    console.clear();
    console.log(`${this.cli.color.magenta('═══ RESPONSE BODY ═══')}\n`);
    console.log(tab.lastResponse.body);
    console.log(`\n${this.cli.color.dim('Press Enter to continue...')}`);
    await prompts({
      type: 'text',
      name: 'continue',
      message: ''
    });
  }

  async viewResponseHeaders(tab) {
    if (!tab.lastResponse) return;
    
    console.clear();
    console.log(`${this.cli.color.magenta('═══ RESPONSE HEADERS ═══')}\n`);
    console.log(`Status: ${tab.lastResponse.statusCode} ${tab.lastResponse.statusMessage}`);
    console.log(`Time: ${tab.lastResponse.responseTime}ms\n`);
    Object.entries(tab.lastResponse.headers).forEach(([key, value]) => {
      console.log(`${this.cli.color.cyan(key)}: ${value}`);
    });
    console.log(`\n${this.cli.color.dim('Press Enter to continue...')}`);
    await prompts({
      type: 'text',
      name: 'continue',
      message: ''
    });
  }

  async saveRepeaterRequest(tab) {
    const filename = await prompts({
      type: 'text',
      name: 'value',
      message: 'Filename:',
      initial: `repeater-${tab.id}.txt`
    });

    if (filename.value) {
      try {
        writeFileSync(filename.value, tab.serializeRequest());
        console.log(`${this.cli.color.green('[✓]')} Saved to ${filename.value}`);
      } catch (err) {
        console.log(`${this.cli.color.red('[✗]')} Error: ${err.message}`);
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
        console.log(`${this.cli.color.green('[✓]')} Request loaded from ${filename.value}`);
      } catch (err) {
        console.log(`${this.cli.color.red('[✗]')} Error: ${err.message}`);
      }
      await this.pause();
    }
  }

  async pause() {
    console.log(`${this.cli.color.dim('\nPress Enter to continue...')}`);
    await prompts({
      type: 'text',
      name: 'continue',
      message: ''
    });
  }

  showHistory() {
    console.log(`\n${this.cli.color.bold(`═══ HISTORY (${this.history.length} requests) ═══`)}`);
    this.history.slice(-10).forEach(entry => {
      const statusColor = entry.status < 300 ? this.cli.color.green :
                         entry.status < 400 ? this.cli.color.yellow : this.cli.color.red;
      console.log(`[${entry.id}] ${entry.method} ${entry.url} ${statusColor(entry.status)}`);
    });
    
    if (this.repeaterTabs.length > 0) {
      console.log(`\n${this.cli.color.bold(`═══ REPEATER (${this.repeaterTabs.length} tabs) ═══`)}`);
      this.repeaterTabs.forEach(tab => {
        const info = tab.lastResponse ? 
          `${tab.lastResponse.statusCode} (${tab.responseHistory.length} sends)` : 
          'not sent';
        console.log(`[${tab.id}] ${tab.method} ${tab.hostname}${tab.path} - ${info}`);
      });
    }
    console.log('');
  }
}

function showHelp(cli) {
  console.log(`
${cli.color.bold.cyan('CLIPI')} ${cli.color.dim('- CLI Proxy Interceptor v1.1.0')}
${cli.color.dim('═══════════════════════════════════════════════════')}

${cli.color.bold('USAGE')}
  clipi [options]
  clipi repeater              ${cli.color.dim('# Open Repeater mode')}

${cli.color.bold('OPTIONS')}
  ${cli.color.yellow('-h, --help')}        Show this help message
  ${cli.color.yellow('-H, --host')}        Proxy host (default: 127.0.0.1)
  ${cli.color.yellow('-p, --port')}        Proxy port (default: 8080)
  ${cli.color.yellow('-i, --intercept')}   Enable manual intercept mode
  ${cli.color.yellow('-v, --verbose')}     Show detailed headers and bodies
  ${cli.color.yellow('--version')}         Show version number

${cli.color.bold('EXAMPLES')}
  ${cli.color.dim('$')} clipi
  ${cli.color.dim('$')} clipi -i
  ${cli.color.dim('$')} clipi -p 9090 -v
  ${cli.color.dim('$')} clipi -H 0.0.0.0 -i -v
  ${cli.color.dim('$')} clipi repeater

${cli.color.bold('PROXY CONFIGURATION')}
  Configure your browser or application:
    Host: 127.0.0.1
    Port: 8080

${cli.color.bold('FEATURES')}
  ${cli.color.green('✓')} HTTP/HTTPS interception
  ${cli.color.green('✓')} Request forwarding and blocking
  ${cli.color.green('✓')} Request modification with editor
  ${cli.color.green('✓')} Repeater with multiple tabs
  ${cli.color.green('✓')} Request history tracking
  ${cli.color.green('✓')} Verbose mode for debugging
  `);
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
    cli: cli
  };

  console.log(`${cli.color.cyan('╔═══════════════════════════════════════╗')}`);
  console.log(`${cli.color.cyan('║')}      ${cli.color.bold.white('CLIPI v1.1.0')}                     ${cli.color.cyan('║')}`);
  console.log(`${cli.color.cyan('║')}  ${cli.color.dim('CLI Proxy Interceptor')}                ${cli.color.cyan('║')}`);
  console.log(`${cli.color.cyan('╚═══════════════════════════════════════╝')}\n`);

  const proxy = new CLIPI(options);

  // Check if repeater mode
  if (cli.o && cli.o.some(arg => arg[0] === 'repeater')) {
    await proxy.openRepeater();
    process.exit(0);
  }

  proxy.start();

  // Allow opening repeater with Ctrl+R (but this requires raw mode)
  process.stdin.on('data', async (key) => {
    if (key.toString() === '\x12') { // Ctrl+R
      await proxy.openRepeater();
    }
  });

  process.on('SIGINT', () => {
    console.log(`\n${cli.color.yellow('[*] Stopping proxy...')}`);
    proxy.showHistory();
    process.exit(0);
  });
}

main();

export default CLIPI;