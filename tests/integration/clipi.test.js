import { describe, it, expect, beforeAll } from "vitest";
import { spawn, execSync } from "child_process";
import { access, constants, readFile, rename, unlink } from 'fs/promises';
import pty from 'node-pty';

/*
const killAndWait = async (process) => {
  if (!process || process.killed) return;
  
  process.kill('SIGTERM');
  
  await new Promise((resolve) => {
    const timeout = setTimeout(resolve, 200);
    process.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });
  });
  
  if (!process.killed) {
    process.kill('SIGKILL');
  }
};
*/


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

const runCLIPI = (args = "", keepAlive = false, interactive = false) => {
  return new Promise((resolve, reject) => {
    const argsArray = args.trim() ? args.trim().split(/\s+/) : [];
    
    let childProcess;
    
    if (interactive) {
      // Usar pty para emular un terminal real
      childProcess = pty.spawn("node", ["clipi.js", ...argsArray], {
        name: 'xterm-color',
        cols: 80,
        rows: 30,
        cwd: process.cwd(),
        env: {
          ...process.env,
          FORCE_COLOR: "0",
          TERM: "xterm-256color"
        }
      });
    } else {
      childProcess = spawn("node", ["clipi.js", ...argsArray], {
        env: {
          ...process.env,
          FORCE_COLOR: "0",
          TERM: "xterm-256color"
        },
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







describe("CLIPI E2E", async () => {
  // Make sure curl is installed cuz this tests are using it to test the proxy
  beforeAll(() => {
    if (!isCurlInstalled()) {
      throw new Error("\n\n❌ curl is required to run integration tests. Please install curl first.\n");
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



  /* INTERCEPR FLAG */
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


  clipiProcess.kill();


/*
// up
sendInput('\x1b[A');

// down
sendInput('\x1b[B');

// left
sendInput('\x1b[D');

// right
sendInput('\x1b[C');
*/
});
