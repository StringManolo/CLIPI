#!/usr/bin/env node

import http from 'node:http';

let currentCommand = { action: 'none' };

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        currentCommand = JSON.parse(body);
        console.log('[+] Order:', currentCommand);
        res.writeHead(200);
        res.end('OK');
      } catch (e) {
        console.error('[!] JSON Error:', body);
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });
  } else {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(currentCommand));
    currentCommand = { action: 'none' };
  }
});

server.listen(3000, '127.0.0.1', () => {
  console.log('[-] ES Server running at http://127.0.0.1:3000');
});
