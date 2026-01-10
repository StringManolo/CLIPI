#!/usr/bin/env node

import http from 'http';
import https from 'https';
import net from 'net';
import { parse as parseUrl } from 'url';
import { createInterface } from 'readline';
import { writeFileSync, readFileSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { tmpdir, homedir } from 'os';
import { spawnSync } from 'child_process';
import { join } from 'path';
import forge from 'node-forge';
import parseCLI from 'simpleargumentsparser';

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
      const result = await this.interceptRequest(clientReq, requestBody, hostname, path);
      
      if (result.action === 'drop') {
        clientRes.writeHead(403);
        clientRes.end('Request blocked by proxy');
        return;
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

  async interceptRequest(req, body, hostname, path) {
    console.log(`\n${this.cli.color.yellow('╔═══ REQUEST INTERCEPTED ═══╗')}`);
    console.log(`${this.cli.color.yellow('Method:')} ${req.method}`);
    console.log(`${this.cli.color.yellow('URL:')} ${hostname}${path}`);
    console.log(`${this.cli.color.yellow('Headers:')}`);
    Object.entries(req.headers).forEach(([key, value]) => {
      console.log(`  ${key}: ${value}`);
    });
    if (body) {
      console.log(`${this.cli.color.yellow('Body:')}\n${body.substring(0, 300)}`);
    }
    console.log(`${this.cli.color.yellow('╚═══════════════════════════╝')}\n`);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout
    });

    return new Promise((resolve) => {
      rl.question(`${this.cli.color.cyan('[f]orward, [d]rop, [m]odify: ')}`, (answer) => {
        rl.close();
        
        if (answer.toLowerCase() === 'd') {
          console.log(`${this.cli.color.red('[x] Request dropped')}\n`);
          resolve({ action: 'drop' });
        } else if (answer.toLowerCase() === 'm') {
          const rawRequest = this.serializeRequest(req.method, hostname, path, req.headers, body);
          const modified = this.openEditor(rawRequest);
          
          if (modified) {
            try {
              const parsed = this.parseModifiedRequest(modified);
              console.log(`${this.cli.color.green('[✓] Request modified')}\n`);
              resolve({ action: 'modify', data: parsed });
            } catch (err) {
              console.log(`${this.cli.color.red('[!] Invalid request format, forwarding original')}\n`);
              resolve({ action: 'forward' });
            }
          } else {
            console.log(`${this.cli.color.yellow('[!] Editor closed, forwarding original')}\n`);
            resolve({ action: 'forward' });
          }
        } else {
          console.log(`${this.cli.color.green('[→] Request forwarded')}\n`);
          resolve({ action: 'forward' });
        }
      });
    });
  }

  showHistory() {
    console.log(`\n${this.cli.color.bold(`═══ HISTORY (${this.history.length} requests) ═══`)}`);
    this.history.slice(-10).forEach(entry => {
      const statusColor = entry.status < 300 ? this.cli.color.green :
                         entry.status < 400 ? this.cli.color.yellow : this.cli.color.red;
      console.log(`[${entry.id}] ${entry.method} ${entry.url} ${statusColor(entry.status)}`);
    });
    console.log('');
  }
}

function showHelp(cli) {
  console.log(`
${cli.color.bold.cyan('CLIPI')} ${cli.color.dim('- CLI Proxy Interceptor v1.0.0')}
${cli.color.dim('═══════════════════════════════════════════════════')}

${cli.color.bold('USAGE')}
  clipi [options]

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

${cli.color.bold('PROXY CONFIGURATION')}
  Configure your browser or application:
    Host: 127.0.0.1
    Port: 8080

${cli.color.bold('FEATURES')}
  ${cli.color.green('✓')} HTTP/HTTPS interception
  ${cli.color.green('✓')} Request forwarding and blocking
  ${cli.color.green('✓')} Request history tracking
  ${cli.color.green('✓')} Verbose mode for debugging
  ${cli.color.green('✓')} Manual intercept mode
  `);
}

async function main() {
  const cli = await parseCLI();

  if (cli.s.h || cli.c.help) {
    showHelp(cli);
    process.exit(0);
  }

  if (cli.c.version) {
    console.log(cli.color.bold('CLIPI v1.0.0'));
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
  console.log(`${cli.color.cyan('║')}      ${cli.color.bold.white('CLIPI v1.0.0')}                     ${cli.color.cyan('║')}`);
  console.log(`${cli.color.cyan('║')}  ${cli.color.dim('CLI Proxy Interceptor')}                ${cli.color.cyan('║')}`);
  console.log(`${cli.color.cyan('╚═══════════════════════════════════════╝')}\n`);

  const proxy = new CLIPI(options);
  proxy.start();

  process.on('SIGINT', () => {
    console.log(`\n${cli.color.yellow('[*] Stopping proxy...')}`);
    proxy.showHistory();
    process.exit(0);
  });
}

main();

export default CLIPI;
