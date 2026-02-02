import { describe, it, expect, beforeAll } from "vitest";
import { spawn, execSync } from "child_process";
import { access, constants, readFile, rename, unlink } from 'fs/promises';
import pty from 'node-pty';

const checkFile = async path => {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

const getFileContent = async path => {
  try {
    const data = await readFile(path, 'utf8');
    return data;
  } catch (error) {
    console.error('Error al leer:', error.message);
    return null;
  }
}

const moveFile = async (source, destination) => {
  try {
    await access(source, constants.F_OK);
    await rename(source, destination);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

const deleteFile = async path => {
  try {
    await access(path, constants.F_OK);
    await unlink(path);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

const sleep = async s => await new Promise(resolve => setTimeout(resolve, s * 1000));

const stripAnsi = (str) => str.replace(/\u001b\[[0-9;]*m/g, '');

const runCLIPI = (args = "", keepAlive = false, interactive = false, customEnv = {}) => {
  return new Promise((resolve, reject) => {
    const argsArray = args.trim() ? args.trim().split(/\s+/) : [];

    let childProcess;

    const env = {
      ...process.env,
      FORCE_COLOR: "0",
      TERM: "xterm-256color",
      ...customEnv  // Permite override de variables de entorno
    };

    if (interactive) {
      childProcess = pty.spawn("node", ["clipi.js", ...argsArray], {
        name: 'xterm-color',
        cols: 80,
        rows: 30,
        cwd: process.cwd(),
        env: env
      });
    } else {
      childProcess = spawn("node", ["clipi.js", ...argsArray], {
        env: env,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    }

    let output = "";
    let errorOutput = "";

    if (interactive) {
      childProcess.onData((data) => {
        output += data;

        if (output.includes("started on") || output.includes("CLIPI started")) {
          setTimeout(() => {
            if (keepAlive) {
              resolve({
                getOutput: () => stripAnsi(output + errorOutput),
                process: childProcess,
                sendInput: (data) => {
                  childProcess.write(data);
                }
              });
            } else {
              childProcess.kill('SIGTERM');
            }
          }, 100);
        }
      });
    } else {
      childProcess.stdout.on("data", (data) => {
        const text = data.toString();
        output += text;

        if (output.includes("started on") || output.includes("CLIPI started")) {
          setTimeout(() => {
            if (keepAlive) {
              resolve({
                getOutput: () => stripAnsi(output + errorOutput),
                process: childProcess
              });
            } else {
              childProcess.kill('SIGTERM');
            }
          }, 100);
        }
      });

      childProcess.stderr.on("data", (data) => {
        errorOutput += data.toString();
      });
    }

    if (!keepAlive && !interactive) {
      childProcess.on('exit', () => {
        resolve(stripAnsi(output + errorOutput));
      });
    }

    setTimeout(() => {
      if (!keepAlive) {
        childProcess.kill('SIGKILL');
        reject(new Error("Timeout - no output detected"));
      }
    }, 3000);

    childProcess.on("error", reject);
  });
};

const isCurlInstalled = () => {
  try {
    execSync("curl --version", { stdio: 'ignore' });
    return true;
  } catch(err) {
    return false;
  }
};

const isEdInstalled = () => {
  try {
    execSync("ed --version", { stdio: 'ignore' });
    return true;
  } catch(err) {
    return false;
  }
};

describe("CLIPI E2E", async () => {
  // Make sure curl and ed are installed cuz this tests are using them for testing proxy features
  beforeAll(() => {
    if (!isCurlInstalled()) {
      throw new Error("\n\n❌ curl is required to run integration tests. Please install curl first.\n");
    }
    
    if (!isEdInstalled()) {
      throw new Error("\n\n❌ ed is required to run integration tests. Please install ed first.\n");
    }

  });

  // Test the software starts in default mode without flags
  const clipiOutputNoArgs = await runCLIPI();
  it("Should bind auto to 127.0.0.1:8080", () => {
    expect(clipiOutputNoArgs).toContain("CLIPI started on 127.0.0.1:8080");
  });

  it("Should start in passive intercept mode", () => {
    expect(clipiOutputNoArgs).toContain("Intercept mode: PASSIVE");
  });

  // Test proxy with curl using HTTP
  let { getOutput, process: clipiProcess } = await runCLIPI("", true);
  await sleep(0.1);
  let exampleResponseFromCurl = execSync("curl --proxy http://127.0.0.1:8080 http://example.com --silent -v 2>&1", { encoding: "utf8" });
  await sleep(0.1);
  const httpExampleRequestOutput = getOutput();
  clipiProcess.kill();
  it("Should get example.com HTTP request in pasive mode", () => {
    expect(httpExampleRequestOutput).toContain("[1] GET example.com/");
  });
  it("Should get 200 HTTP status code from example.com request in pasive mode", () => {
    expect(httpExampleRequestOutput).toContain("200 OK");
  });
  it("Should get example.com server headers from CURL output", () => {
    expect(exampleResponseFromCurl).toContain("Host: example.com");
  });
  it("Should get example.com HTML body from CURL output", () => {
    expect(exampleResponseFromCurl).toContain("<title>Example Domain</title>");
  });

  // Test proxy with curl using HTTPS and MITM with custom certs
  ({ getOutput, process: clipiProcess } = await runCLIPI("", true));
  await sleep(0.1);
  exampleResponseFromCurl = execSync("curl --proxy http://127.0.0.1:8080 https://example.com --cacert ~/.clipi/certs/ca-cert.pem --silent -v 2>&1", { encoding: "utf8" });
  await sleep(0.1);
  const httpsExampleRequestOutput = getOutput();
  clipiProcess.kill();
  it("Should get example.com HTTPS CONNECT request in pasive mode", () => {
    expect(httpsExampleRequestOutput).toContain("[HTTPS] CONNECT example.com:443");
  });
  it("Should get example.com HTTPS request in pasive mode", () => {
    expect(httpsExampleRequestOutput).toContain("[1] GET example.com/ [HTTPS]");
  });
  it("Should get 200 HTTP status code from example.com request in Secure pasive mode", () => {
    expect(httpsExampleRequestOutput).toContain("200 OK");
  });
  it("Should get https://example.com HTML body from CURL output", () => {
    expect(exampleResponseFromCurl).toContain("<title>Example Domain</title>");
  });


  // Test --host flag works
  ({ getOutput, process: clipiProcess } = await runCLIPI("--host 127.0.0.2", true));
  await sleep(0.1);
  exampleResponseFromCurl = execSync("curl --proxy http://127.0.0.2:8080 http://example.com --silent -v 2>&1", { encoding: "utf8" });
  await sleep(0.1);
  const httpExampleRequestHostOutput = getOutput();
  clipiProcess.kill();
  it("Should bind to 127.0.0.2:8080 with --host 127.0.0.2 flag", () => {
    expect(httpExampleRequestHostOutput).toContain("CLIPI started on 127.0.0.2:8080");
  });
  it("Should get example.com HTML body from CURL output with --host 127.0.0.2 flag", () => {
    expect(exampleResponseFromCurl).toContain("<title>Example Domain</title>");
  });

  // Test --port flag works
  ({ getOutput, process: clipiProcess } = await runCLIPI("--port 8081", true));
  await sleep(0.1);
  exampleResponseFromCurl = execSync("curl --proxy http://127.0.0.1:8081 http://example.com --silent -v 2>&1", { encoding: "utf8" });
  await sleep(0.1);
  const httpExampleRequestPortOutput = getOutput();
  clipiProcess.kill();
  it("Should bind to 127.0.0.1:8081 with --port 8081 flag", () => {
    expect(httpExampleRequestPortOutput).toContain("CLIPI started on 127.0.0.1:8081");
  });
  it("Should get example.com HTML body from CURL output with --port 8081 flag", () => {
    expect(exampleResponseFromCurl).toContain("<title>Example Domain</title>");
  });


  // Test --log works
  await moveFile("requests.log", "backup.requests.log");
  ({ getOutput, process: clipiProcess } = await runCLIPI("--log", true));
  await sleep(0.1);
  exampleResponseFromCurl = execSync("curl --proxy http://127.0.0.1:8080 https://example.com --cacert ~/.clipi/certs/ca-cert.pem --silent -v 2>&1", { encoding: "utf8" });
  await sleep(0.1);
  const httpsExampleRequestLogOutput = getOutput();
  clipiProcess.kill();
  it("Should detect --log flag as ENABLED", () => {
    expect(httpsExampleRequestLogOutput).toContain("Logging: ENABLED → requests.log");
  });
  it("Should create file requests.log", async () => {
    await checkFile("requests.log");
  });
  const logFileContent = await getFileContent("requests.log");
  it("Should log session start", () => {
    expect(logFileContent).toContain("CLIPI Log - Session started at");
  });
  it("Should log headers", () => {
    expect(logFileContent).toContain("] Headers: {");
  });
  it("Should log example.com request headers", () => {
    expect(logFileContent).toContain('"host": "example.com",');
  });
  it("Should log example.com response headers", () => {
    expect(logFileContent).toContain('"allow": "GET, HEAD",');
  });
  it("Should log example.com HTTPS response body", () => {
    expect(logFileContent).toContain('Body: <!doctype html><html lang="en"><head><title>Example Domain</title>');
  });
  await deleteFile("requests.log");
  await moveFile("backup.requests.log", "requests.log");

  /* INTERCEPT FLAG */
  // Test --intercept works
  ({ getOutput, process: clipiProcess } = await runCLIPI("--intercept", true));
  await sleep(0.1);
  const curlProcess = spawn("curl", [
    "--proxy", "http://127.0.0.1:8080",
    "https://example.com",
    "--cacert", `${process.env.HOME}/.clipi/certs/ca-cert.pem`,
    "--silent", "-v"
  ], {
    shell: true,
    stdio: 'pipe'
  });

  let exampleResponseFromCurlAsync = "";
  curlProcess.stdout.on('data', d => exampleResponseFromCurlAsync += d.toString());
  curlProcess.stderr.on('data', d => exampleResponseFromCurlAsync += d.toString());
  curlProcess.kill();
  await sleep(0.1);
  const httpsExampleRequestInterceptOutput = getOutput();

  clipiProcess.kill();
  it("Should detect --intercept flag as ACTIVE", () => {
    expect(httpsExampleRequestInterceptOutput).toContain("Intercept mode: ACTIVE");
  });

  // Test --intercept forward request works
  let sendInput;
  ({ getOutput, process: clipiProcess, sendInput } = await runCLIPI("--intercept", true, true));

  await sleep(0.1);
  const curlProcessForward = spawn("curl", [
  "--proxy", "http://127.0.0.1:8080",
  "https://example.com",
  "--cacert", `${process.env.HOME}/.clipi/certs/ca-cert.pem`,
  "--silent", "-v"
], {
  shell: true,
  stdio: 'pipe'
});
  await sleep(2);
  let exampleResponseFromCurlAsync2 = "";
  curlProcessForward.stdout.on('data', d => exampleResponseFromCurlAsync2 += d.toString());
  curlProcessForward.stderr.on('data', d => exampleResponseFromCurlAsync2 += d.toString());
  const httpsExampleRequestInterceptForwardOutput = getOutput();
  it("Should show Forward option", () => {
    expect(httpsExampleRequestInterceptForwardOutput).toContain("Forward - Send request as-is");
  });

  // Send ENTER to CLIPI to select forward option.
  await sleep(0.5);
  sendInput('\n');
  await sleep(2);
  it("Should Forward https://example.com response request body to CURL", () => {
    expect(exampleResponseFromCurlAsync2).toContain('<!doctype html><html lang="en"><head><title>Example Domain</title>');
  });




  // Drop request
  const curlProcessDrop = spawn("curl", [
  "--proxy", "http://127.0.0.1:8080",
  "https://example.com",
  "--cacert", `${process.env.HOME}/.clipi/certs/ca-cert.pem`,
  "--silent", "-v"
], {
  shell: true,
  stdio: 'pipe'
});
  await sleep(2);
  let exampleResponseFromCurlAsync3 = "";
  curlProcessDrop.stdout.on('data', d => exampleResponseFromCurlAsync3 += d.toString());
  curlProcessDrop.stderr.on('data', d => exampleResponseFromCurlAsync3 += d.toString())

  await sleep(2);
  const httpsExampleRequestInterceptDropOutput = getOutput();
  it("Should show Drop option", () => {
    expect(httpsExampleRequestInterceptDropOutput).toContain("✗ Drop");
  });

  // Send ARROW_UP & ENTER to CLIPI to select drop option.
  await sleep(0.5);
  sendInput("\x1b[A");
  await sleep(0.1);
  sendInput('\n');
  await sleep(2);
  const httpsExampleRequestInterceptDrop2Output = getOutput();
  it("Should show drop message confirmation", () => {
    expect(httpsExampleRequestInterceptDrop2Output).toContain("[✗] Request dropped");
  });

  it("Should show Request blocked by proxy response", () => {
    expect(exampleResponseFromCurlAsync3).toContain("Request blocked by proxy");
  });






  // Modify request with ed editor
  clipiProcess.kill();
  ({ getOutput, process: clipiProcess, sendInput } = await runCLIPI("--intercept", true, true, {
    EDITOR: "ed",
    VISUAL: "ed"
  }));

  await sleep(0.1);
  const curlProcessModify = spawn("curl", [
    "--proxy", "http://127.0.0.1:8080",
    "https://example.com",
    "--cacert", `${process.env.HOME}/.clipi/certs/ca-cert.pem`,
    "--silent", "-v"
  ], {
    shell: true,
    stdio: 'pipe'
  });

  await sleep(2);
  let exampleResponseFromCurlAsync4 = "";
  curlProcessModify.stdout.on('data', d => exampleResponseFromCurlAsync4 += d.toString());
  curlProcessModify.stderr.on('data', d => exampleResponseFromCurlAsync4 += d.toString())

  await sleep(2);
  const httpsExampleRequestInterceptModifyOutput = getOutput();
  it("Should show modify option", () => {
    expect(httpsExampleRequestInterceptModifyOutput).toContain("Modify");
  });

  // Select modify (arrow down + enter)
  await sleep(0.5);
  sendInput("\x1b[B"); // Arrow down
  await sleep(0.1);
  sendInput('\n'); // enter to select modify option
  await sleep(1);

  // send q to quit ed
  sendInput('q\n');
  await sleep(2);

  const httpsExampleRequestInterceptModify2Output = getOutput();
  it("Should detect request modified", () => {
    expect(httpsExampleRequestInterceptModify2Output).toContain("[✓] Request modified");
  });

  await sleep(1);
  it("Should get response after closing editor without changes", () => {
    expect(exampleResponseFromCurlAsync4).toContain('<!doctype html><html lang="en"><head><title>Example Domain</title>');
  });
  curlProcessModify.kill();
  



  // Modify request replacing "GET / HTTP/1.1" by "POST / HTTP/1.1" 
  const curlProcessModifyPost = spawn("curl", [
    "--proxy", "http://127.0.0.1:8080",
    "https://example.com",
    "--cacert", `${process.env.HOME}/.clipi/certs/ca-cert.pem`,
    "--silent", "-v"
  ], {
    shell: true,
    stdio: 'pipe'
  });

  await sleep(2);
  let exampleResponseFromCurlAsync5 = "";
  curlProcessModifyPost.stdout.on('data', d => exampleResponseFromCurlAsync5 += d.toString());
  curlProcessModifyPost.stderr.on('data', d => exampleResponseFromCurlAsync5 += d.toString())

  await sleep(2);
  const httpsExampleRequestInterceptModifyPostOutput = getOutput();
  it("Should show modify option", () => {
    expect(httpsExampleRequestInterceptModifyPostOutput).toContain("Modify");
  });

  // Select modify (arrow down + enter)
  await sleep(0.5);
  sendInput("\x1b[B"); // Arrow down
  await sleep(0.1);
  sendInput('\n'); // enter to select modify option
  await sleep(1);

  // replace GET by POST
  sendInput("1s/GET/POST/\n");
  // send wq to save and quit ed
  sendInput('wq\n');
  await sleep(2);

  const httpsExampleRequestInterceptModifyPost2Output = getOutput();
  it("Should detect request modified", () => {
    expect(httpsExampleRequestInterceptModifyPost2Output).toContain("[✓] Request modified");
  });

  it("Should get 405 Method Not Allowed from CLIPI", () => {
    expect(httpsExampleRequestInterceptModifyPost2Output).toContain("405 Method Not Allowed");
  });

  it("Should get 405 Method Not Allowed from curl -v", () => {
    expect(exampleResponseFromCurlAsync5).toContain("405 Method Not Allowed");
  });


  curlProcessModify.kill();
  clipiProcess.kill();

  // TODO: Add tests for repeater

// Add at the end of clipi.test.js, before the closing describe()
/* ═══════════════════════════════════════════════════════════
   REPEATER TESTS
   ═══════════════════════════════════════════════════════════ */

/*

// Backup repeater tabs file before tests
await moveFile(
  `${process.env.HOME}/.clipi/repeater-tabs.json`,
  `${process.env.HOME}/.clipi/backup-repeater-tabs.json`
);

// Send two requests to repeater
clipiProcess.kill();
({ getOutput, process: clipiProcess, sendInput } = await runCLIPI("--intercept", true, true));

await sleep(0.1);

// First request to repeater - GET example.com
const curlRepeater1 = spawn("curl", [
  "--proxy", "http://127.0.0.1:8080",
  "https://example.com",
  "--cacert", `${process.env.HOME}/.clipi/certs/ca-cert.pem`,
  "--silent", "-v"
], {
  shell: true,
  stdio: 'pipe'
});

await sleep(2);
sendInput("\x1b[B"); // Arrow down
await sleep(0.1);
sendInput("\x1b[B"); // Arrow down to Repeater
await sleep(0.1);
sendInput('\n'); // Select Repeater
await sleep(1);

const repeaterOutput1 = getOutput();
it("Should send first request to Repeater", () => {
  expect(repeaterOutput1).toContain("Request sent to Repeater");
});

curlRepeater1.kill();

// Second request to repeater - GET httpbin.org/get
const curlRepeater2 = spawn("curl", [
  "--proxy", "http://127.0.0.1:8080",
  "https://httpbin.org/get",
  "--cacert", `${process.env.HOME}/.clipi/certs/ca-cert.pem`,
  "--silent", "-v"
], {
  shell: true,
  stdio: 'pipe'
});

await sleep(2);
sendInput("\x1b[B"); // Arrow down
await sleep(0.1);
sendInput("\x1b[B"); // Arrow down to Repeater
await sleep(0.1);
sendInput('\n'); // Select Repeater
await sleep(1);

const repeaterOutput2 = getOutput();
it("Should send second request to Repeater", () => {
  expect(repeaterOutput2).toContain("Request sent to Repeater");
});

curlRepeater2.kill();
clipiProcess.kill();

// Test repeater tabs file was created
it("Should create repeater-tabs.json file", async () => {
  const exists = await checkFile(`${process.env.HOME}/.clipi/repeater-tabs.json`);
  expect(exists).toBe(true);
});

// Read and verify tabs content
const repeaterTabsContent = await getFileContent(`${process.env.HOME}/.clipi/repeater-tabs.json`);
it("Should have 2 tabs in repeater file", () => {
  const tabs = JSON.parse(repeaterTabsContent);
  expect(tabs.length).toBe(2);
});

it("Should have example.com tab", () => {
  const tabs = JSON.parse(repeaterTabsContent);
  expect(tabs.some(t => t.hostname === "example.com")).toBe(true);
});

it("Should have httpbin.org tab", () => {
  const tabs = JSON.parse(repeaterTabsContent);
  expect(tabs.some(t => t.hostname === "httpbin.org")).toBe(true);
});

// Test opening repeater with 'repeater' command using PTY
const repeaterCliProcess = pty.spawn("node", ["clipi.js", "repeater"], {
  name: 'xterm-color',
  cols: 80,
  rows: 30,
  cwd: process.cwd(),
  env: {
    ...process.env,
    FORCE_COLOR: "0",
    TERM: "xterm-256color",
    EDITOR: "ed",
    VISUAL: "ed"
  }
});

let repeaterCliOutput = "";
repeaterCliProcess.onData((data) => {
  repeaterCliOutput += data;
});

await sleep(3);
it("Should open repeater with 'repeater' command", () => {
  expect(stripAnsi(repeaterCliOutput)).toContain("CLIPI REPEATER");
});

it("Should show both tabs in repeater menu", () => {
  const output = stripAnsi(repeaterCliOutput);
  expect(output).toContain("example.com");
  expect(output).toContain("httpbin.org");
});

repeaterCliProcess.kill();
console.log("DEBUG TESTS1");
// Test repeater functionality interactively
({ getOutput, process: clipiProcess, sendInput } = await runCLIPI("repeater", true, true, {
  EDITOR: "ed",
  VISUAL: "ed"
}));
console.log("DEBUG TESTS2");
clipiProcess.kill();
console.log("DEBUG TESTS3");
/*

await sleep(2);
const repeaterMenuOutput = getOutput();
it("Should open repeater menu", () => {
  expect(repeaterMenuOutput).toContain("CLIPI REPEATER");
});

// Select first tab (example.com)
sendInput('\n'); // Select first tab
await sleep(2);

const tabMenuOutput = getOutput();
it("Should open tab menu for example.com", () => {
  expect(tabMenuOutput).toContain("REPEATER TAB");
  expect(tabMenuOutput).toContain("example.com");
});


// Test Send request
sendInput('\n'); // Select Send (first option)
await sleep(4);

const sendOutput = getOutput();
it("Should send request from repeater", () => {
  expect(sendOutput).toContain("Sending request");
});

it("Should get 200 OK response from example.com", () => {
  expect(sendOutput).toContain("200");
});

// Press enter to continue
sendInput('\n');
await sleep(1);

// Test View Request
sendInput("\x1b[B"); // Arrow down to View Request
await sleep(0.1);
sendInput('\n'); // Select
await sleep(2);

const viewRequestOutput = getOutput();
it("Should show raw HTTP request", () => {
  expect(viewRequestOutput).toContain("RAW HTTP REQUEST");
  expect(viewRequestOutput).toContain("GET");
  expect(viewRequestOutput).toContain("example.com");
});

sendInput('\n'); // Continue
await sleep(1);

// Test Edit request
sendInput("\x1b[B"); // Arrow down to Edit
await sleep(0.1);
sendInput('\n'); // Select Edit
await sleep(2);

// Change GET to POST using ed
sendInput("1s/GET/POST/\n");
await sleep(0.5);
sendInput("wq\n");
await sleep(3);

const editOutput = getOutput();
it("Should update request after edit", () => {
  expect(editOutput).toContain("Request updated");
});

sendInput('\n'); // Continue
await sleep(1);

// Send modified request (POST)
sendInput('\n'); // Select Send
await sleep(4);

const postSendOutput = getOutput();
it("Should send modified POST request", () => {
  expect(postSendOutput).toContain("Sending request");
});

it("Should get 405 Method Not Allowed for POST to example.com", () => {
  expect(postSendOutput).toContain("405");
});

sendInput('\n'); // Continue
await sleep(1);

// Navigate to View Response (3 downs from current position)
sendInput("\x1b[B"); // Arrow down
await sleep(0.1);
sendInput("\x1b[B"); // Arrow down
await sleep(0.1);
sendInput("\x1b[B"); // Arrow down to View Response
await sleep(0.1);
sendInput('\n'); // Select View Response
await sleep(2);

const viewResponseOutput = getOutput();
it("Should show response body", () => {
  expect(viewResponseOutput).toContain("RESPONSE BODY");
});

sendInput('\n'); // Continue
await sleep(1);

// Test View Headers
sendInput("\x1b[B"); // Arrow down to Headers
await sleep(0.1);
sendInput('\n'); // Select
await sleep(2);

const headersOutput = getOutput();
it("Should show response headers", () => {
  expect(headersOutput).toContain("RESPONSE HEADERS");
  expect(headersOutput).toContain("Status:");
});

sendInput('\n'); // Continue
await sleep(1);

// Edit back to GET for remaining tests
sendInput("\x1b[B"); // Arrow down
await sleep(0.1);
sendInput("\x1b[B"); // Arrow down to Edit
await sleep(0.1);
sendInput('\n'); // Select Edit
await sleep(2);

sendInput("1s/POST/GET/\n");
await sleep(0.5);
sendInput("wq\n");
await sleep(3);
sendInput('\n'); // Continue
await sleep(1);

// Send GET request to have good response for search
sendInput('\n'); // Select Send
await sleep(4);
sendInput('\n'); // Continue
await sleep(1);

// Navigate to Search (5 downs)
for (let i = 0; i < 5; i++) {
  sendInput("\x1b[B");
  await sleep(0.1);
}
sendInput('\n'); // Select Search
await sleep(1);

// Type search query
sendInput("Example\n"); // Search for "Example"
await sleep(3);

const searchOutput = getOutput();
it("Should search in response body", () => {
  expect(searchOutput).toContain("SEARCH RESULTS");
  expect(searchOutput).toContain("Example");
});

sendInput('\n'); // Continue
await sleep(1);

// Send another request for comparison
sendInput('\n'); // Send
await sleep(4);
sendInput('\n'); // Continue
await sleep(1);

// Navigate to Compare (6 downs)
for (let i = 0; i < 6; i++) {
  sendInput("\x1b[B");
  await sleep(0.1);
}
sendInput('\n'); // Select Compare
await sleep(2);

sendInput('\n'); // Select first response
await sleep(1);
sendInput("\x1b[B"); // Arrow down to second response
await sleep(0.1);
sendInput('\n'); // Select
await sleep(2);

const compareOutput = getOutput();
it("Should compare two responses", () => {
  expect(compareOutput).toContain("RESPONSE COMPARISON");
});

sendInput('\n'); // Continue
await sleep(1);

// Test History
sendInput("\x1b[B"); // Arrow down to History
await sleep(0.1);
sendInput('\n'); // Select History
await sleep(2);

const historyOutput = getOutput();
it("Should show response history", () => {
  expect(historyOutput).toContain("RESPONSE HISTORY");
});

sendInput("\x1b[B"); // Arrow down
await sleep(0.1);
sendInput('\n'); // Select back
await sleep(1);

// Test Copy as cURL
sendInput("\x1b[B"); // Arrow down to Copy as cURL
await sleep(0.1);
sendInput('\n'); // Select
await sleep(2);

const curlOutput = getOutput();
it("Should generate cURL command", () => {
  expect(curlOutput).toContain("cURL COMMAND");
  expect(curlOutput).toContain("curl");
  expect(curlOutput).toContain("example.com");
});

// Save cURL to file
sendInput('\n'); // Select save to file
await sleep(1);
sendInput("test-curl.sh\n"); // Filename
await sleep(3);

it("Should create test-curl.sh file", async () => {
  await sleep(1);
  const exists = await checkFile("test-curl.sh");
  expect(exists).toBe(true);
});

const curlFileContent = await getFileContent("test-curl.sh");
it("Should have valid cURL script", () => {
  expect(curlFileContent).toContain("#!/bin/bash");
  expect(curlFileContent).toContain("curl");
});

await deleteFile("test-curl.sh");
sendInput('\n'); // Continue
await sleep(1);

// Navigate to Settings (9 downs from current position)
for (let i = 0; i < 9; i++) {
  sendInput("\x1b[B");
  await sleep(0.1);
}
sendInput('\n'); // Select Settings
await sleep(2);

const settingsOutput = getOutput();
it("Should show settings menu", () => {
  expect(settingsOutput).toContain("SETTINGS");
  expect(settingsOutput).toContain("Follow Redirects:");
});

sendInput('\n'); // Toggle redirects
await sleep(2);

const toggleOutput = getOutput();
it("Should toggle follow redirects", () => {
  expect(toggleOutput).toContain("Follow Redirects:");
});

sendInput('\n'); // Continue
await sleep(1);

// Test Save request to file
sendInput("\x1b[B"); // Arrow down to Save
await sleep(0.1);
sendInput('\n'); // Select Save
await sleep(1);

sendInput("test-request.txt\n"); // Filename
await sleep(2);

it("Should save request to file", async () => {
  await sleep(1);
  const exists = await checkFile("test-request.txt");
  expect(exists).toBe(true);
});

const savedRequestContent = await getFileContent("test-request.txt");
it("Should have valid HTTP request in saved file", () => {
  expect(savedRequestContent).toContain("GET");
  expect(savedRequestContent).toContain("example.com");
});

sendInput('\n'); // Continue
await sleep(1);

// Test Load request from file
sendInput("\x1b[B"); // Arrow down to Load
await sleep(0.1);
sendInput('\n'); // Select Load
await sleep(1);

sendInput("test-request.txt\n"); // Filename
await sleep(2);

const loadOutput = getOutput();
it("Should load request from file", () => {
  expect(loadOutput).toContain("Request loaded");
});

await deleteFile("test-request.txt");
sendInput('\n'); // Continue
await sleep(1);

// Test Delete Tab
sendInput("\x1b[B"); // Arrow down
await sleep(0.1);
sendInput("\x1b[B"); // Arrow down to Delete
await sleep(0.1);
sendInput('\n'); // Select Delete
await sleep(1);

// Navigate to Yes for confirmation
sendInput("\x1b[D"); // Arrow left to Yes
await sleep(0.1);
sendInput('\n'); // Confirm
await sleep(2);

const deleteOutput = getOutput();
it("Should delete repeater tab", () => {
  expect(deleteOutput).toContain("Tab deleted");
});

await sleep(1);

// Verify only 1 tab remains
const finalTabsContent = await getFileContent(`${process.env.HOME}/.clipi/repeater-tabs.json`);
it("Should have only 1 tab after deletion", () => {
  const tabs = JSON.parse(finalTabsContent);
  expect(tabs.length).toBe(1);
});

it("Should have httpbin.org tab remaining", () => {
  const tabs = JSON.parse(finalTabsContent);
  expect(tabs[0].hostname).toBe("httpbin.org");
});

// Exit repeater (should auto-return to tab list)
await sleep(1);

// Exit from tab list
sendInput("\x1b[B"); // Arrow down to Back
await sleep(0.1);
sendInput('\n'); // Select Back
await sleep(2);

clipiProcess.kill();

// Test persistence - reopen and verify tabs
({ getOutput, process: clipiProcess, sendInput } = await runCLIPI("repeater", true, true));
await sleep(3);

const persistenceOutput = getOutput();
it("Should persist tabs between sessions", () => {
  expect(persistenceOutput).toContain("CLIPI REPEATER");
  expect(persistenceOutput).toContain("httpbin.org");
});

it("Should not show deleted tab after session restart", () => {
  expect(persistenceOutput).not.toContain("Tab 1:");
});

// Exit
sendInput("\x1b[B"); // Arrow down to Back
await sleep(0.1);
sendInput('\n'); // Back
await sleep(1);

clipiProcess.kill();

// Restore backup repeater tabs
await deleteFile(`${process.env.HOME}/.clipi/repeater-tabs.json`);
await moveFile(
  `${process.env.HOME}/.clipi/backup-repeater-tabs.json`,
  `${process.env.HOME}/.clipi/repeater-tabs.json`
);

it("Should restore original repeater tabs after tests", async () => {
  const backupExists = await checkFile(`${process.env.HOME}/.clipi/backup-repeater-tabs.json`);
  if (!backupExists) {
    expect(true).toBe(true);
  }
});
*/
  // TODO: Cleanup on test fails
});
