import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let currentCommand = { action: 'none' };

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url === '/preload.js') {
    try {
      const content = await fs.readFile(path.join(__dirname, 'preload.js'));
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(content);
    } catch (e) {
      res.writeHead(404);
      res.end();
    }
    return;
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        if (req.url === '/data') {
          
          console.log(`\n\x1b[32m[DATA]\x1b[0m From: ${data.url}`);
          console.table(data.results.slice(0, 15));
          await fs.writeFile(`scrape_${Date.now()}.json`, body);
          res.end('OK');
        } else if (req.url === '/spy') {
          console.log(`\n\x1b[33m[SPY]\x1b[0m Selector: \x1b[36m${data.selector}\x1b[0m`);
          console.log(`  Suggest: cromite.page.click('${data.selector}')`);
          res.end('OK');
        } else {
          currentCommand = data;
          res.end('OK');
        }
      } catch (e) {
        console.log(e);
        res.writeHead(400);
        res.end();
      }
    });
  } else {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(currentCommand));
    currentCommand = { action: 'none' };
  }
});

server.listen(3000, '127.0.0.1');
