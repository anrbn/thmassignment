const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");
const pty = require("node-pty");
const { WebSocketServer } = require("ws");

const ROOT_DIR = __dirname;
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 8124);
const LABS_DIR = path.join(ROOT_DIR, "labs");
const LAB_TEMPLATE_DIR = path.join(LABS_DIR, "_fresh");
const RESETTABLE_LAB_FILES = ["soc_script.py", "fullagent.py"];
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const ACCESS_PASSWORD = process.env.LAB_ACCESS_PASSWORD || "tryhackme-3";
const SESSION_COOKIE = "soc_lab_session";
const SESSION_TOKEN = crypto.randomBytes(32).toString("hex");
const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;
const PUBLIC_STATIC_FILES = new Set(["code_editor.html", "thmroom.md"]);
const PUBLIC_STATIC_DIRS = [
  LABS_DIR,
  path.join(ROOT_DIR, "images"),
  path.join(ROOT_DIR, "vendor")
];
const TERMINAL_BLOCKED_COMMANDS = [
  "bash",
  "cmd",
  "cmd.exe",
  "code",
  "explorer",
  "invoke-item",
  "ii",
  "notepad",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
  "sh",
  "start",
  "wsl",
  "wt"
];

const CONTENT_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".png": "image/png",
  ".py": "text/x-python; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
  ".zip": "application/zip"
};

function isInside(parent, target) {
  const relative = path.relative(parent, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function parseCookies(request) {
  const cookies = {};
  const header = request.headers.cookie || "";

  for (const part of header.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (!rawName) {
      continue;
    }

    cookies[rawName] = decodeURIComponent(rawValue.join("=") || "");
  }

  return cookies;
}

function secureEquals(first, second) {
  const firstBuffer = Buffer.from(String(first || ""), "utf8");
  const secondBuffer = Buffer.from(String(second || ""), "utf8");

  return firstBuffer.length === secondBuffer.length && crypto.timingSafeEqual(firstBuffer, secondBuffer);
}

function isAuthenticated(request) {
  return secureEquals(parseCookies(request)[SESSION_COOKIE], SESSION_TOKEN);
}

function sendJson(response, statusCode, body) {
  const payload = JSON.stringify(body);
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload)
  });
  response.end(payload);
}

function sendText(response, statusCode, body, contentType) {
  response.writeHead(statusCode, {
    "Content-Type": contentType || "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  response.end(body);
}

function sendRedirect(response, location) {
  response.writeHead(303, { Location: location });
  response.end();
}

function sendLoginPage(response, statusCode, message) {
  const body = [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Lab Access</title>",
    "<style>",
    ":root{color-scheme:dark;--page:#101827;--panel:#172235;--line:#2c3d5a;--text:#f4f7fb;--muted:#9eacc2;--accent:#39d98a;--danger:#ff6378}",
    "*{box-sizing:border-box}",
    "body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#101827,#10243a);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif}",
    "main{width:min(420px,calc(100vw - 40px));padding:28px;border:1px solid var(--line);border-radius:8px;background:var(--panel);box-shadow:0 24px 80px rgba(0,0,0,.35)}",
    "h1{margin:0 0 8px;font-size:28px;line-height:1.15;letter-spacing:0}",
    "p{margin:0 0 22px;color:var(--muted)}",
    "label{display:block;margin:0 0 8px;font-weight:700}",
    "input{width:100%;height:44px;border:1px solid var(--line);border-radius:6px;background:#0b1220;color:var(--text);padding:0 12px}",
    "button{width:100%;height:44px;margin-top:16px;border:0;border-radius:6px;background:var(--accent);color:#07130d;font-weight:800;cursor:pointer}",
    ".error{margin:0 0 14px;color:var(--danger);font-weight:700}",
    "</style>",
    "</head>",
    "<body>",
    "<main>",
    "<h1>Lab Access</h1>",
    "<p>Enter the room password to continue.</p>",
    message ? `<p class="error">${message}</p>` : "",
    '<form method="post" action="/login">',
    '<label for="password">Password</label>',
    '<input id="password" name="password" type="password" autocomplete="current-password" autofocus required>',
    "<button type=\"submit\">Unlock Lab</button>",
    "</form>",
    "</main>",
    "</body>",
    "</html>"
  ].join("\n");

  response.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  response.end(body);
}

function safeLabFilename(filename) {
  return /^[A-Za-z0-9_.-]+\.py$/.test(filename || "") ? filename : "";
}

async function resetLabFiles() {
  for (const filename of RESETTABLE_LAB_FILES) {
    const templatePath = path.join(LAB_TEMPLATE_DIR, filename);
    const targetPath = path.join(LABS_DIR, filename);

    if (!isInside(LAB_TEMPLATE_DIR, templatePath) || !isInside(LABS_DIR, targetPath)) {
      throw new Error("Invalid lab reset path.");
    }

    await fs.promises.copyFile(templatePath, targetPath);
  }
}

function requestPathname(request) {
  return new URL(request.url, `http://${request.headers.host || `${HOST}:${PORT}`}`).pathname;
}

function resolveStaticPath(urlPathname) {
  const decodedPath = decodeURIComponent(urlPathname);
  const relativePath = decodedPath === "/" ? "code_editor.html" : decodedPath.replace(/^\/+/, "");
  const absolutePath = path.resolve(ROOT_DIR, relativePath);

  if (!isInside(ROOT_DIR, absolutePath)) {
    return null;
  }

  return absolutePath;
}

function hasHiddenPathSegment(baseDirectory, targetPath) {
  return path.relative(baseDirectory, targetPath)
    .split(path.sep)
    .some((segment) => segment.startsWith("."));
}

function isAllowedStaticPath(staticPath) {
  if (!isInside(ROOT_DIR, staticPath) || hasHiddenPathSegment(ROOT_DIR, staticPath)) {
    return false;
  }

  const relativePath = path.relative(ROOT_DIR, staticPath).replace(/\\/g, "/");
  if (PUBLIC_STATIC_FILES.has(relativePath)) {
    return true;
  }

  return PUBLIC_STATIC_DIRS.some((directory) => isInside(directory, staticPath));
}

function directoryListing(urlPathname, directoryPath) {
  const entries = fs.readdirSync(directoryPath, { withFileTypes: true })
    .filter((entry) => !entry.name.startsWith("."))
    .sort((first, second) => first.name.localeCompare(second.name))
    .map((entry) => {
      const href = encodeURIComponent(entry.name) + (entry.isDirectory() ? "/" : "");
      const label = entry.name + (entry.isDirectory() ? "/" : "");
      return `<li><a href="${href}">${label}</a></li>`;
    })
    .join("\n");

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    `<title>Directory listing for ${urlPathname}</title>`,
    "</head>",
    "<body>",
    `<h1>Directory listing for ${urlPathname}</h1>`,
    "<hr>",
    "<ul>",
    entries,
    "</ul>",
    "<hr>",
    "</body>",
    "</html>"
  ].join("\n");
}

function readRawBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";

    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_JSON_BYTES) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });
    request.on("end", () => {
      resolve(body);
    });
    request.on("error", reject);
  });
}

async function readJsonBody(request) {
  try {
    return JSON.parse((await readRawBody(request)) || "{}");
  } catch (error) {
    throw new Error("Invalid JSON body.");
  }
}

async function handleAuth(request, response, urlPathname) {
  if (request.method === "GET" && urlPathname === "/login") {
    if (isAuthenticated(request)) {
      sendRedirect(response, "/code_editor.html");
      return true;
    }

    sendLoginPage(response, 200, "");
    return true;
  }

  if (request.method === "POST" && urlPathname === "/login") {
    const body = await readRawBody(request);
    const form = new URLSearchParams(body);
    const password = form.get("password") || "";

    if (!secureEquals(password, ACCESS_PASSWORD)) {
      sendLoginPage(response, 401, "Incorrect password.");
      return true;
    }

    response.writeHead(303, {
      Location: "/code_editor.html",
      "Set-Cookie": [
        `${SESSION_COOKIE}=${encodeURIComponent(SESSION_TOKEN)}`,
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        `Max-Age=${SESSION_MAX_AGE_SECONDS}`
      ].join("; ")
    });
    response.end();
    return true;
  }

  return false;
}

async function handleApi(request, response, urlPathname) {
  if (request.method === "GET" && urlPathname === "/api/health") {
    sendJson(response, 200, {
      ok: true,
      cwd: LABS_DIR,
      terminal: true
    });
    return true;
  }

  if (request.method === "GET" && urlPathname === "/api/labs") {
    const files = fs.readdirSync(LABS_DIR)
      .filter(safeLabFilename)
      .sort((first, second) => first.localeCompare(second));
    sendJson(response, 200, { files });
    return true;
  }

  if (request.method === "POST" && urlPathname === "/api/save-lab-file") {
    try {
      const payload = await readJsonBody(request);
      const filename = safeLabFilename(payload.filename);

      if (!filename) {
        sendJson(response, 400, { ok: false, error: "Invalid Python filename." });
        return true;
      }

      const targetPath = path.join(LABS_DIR, filename);
      if (!isInside(LABS_DIR, targetPath)) {
        sendJson(response, 400, { ok: false, error: "Invalid lab file path." });
        return true;
      }

      await fs.promises.writeFile(targetPath, String(payload.content || ""), "utf8");
      sendJson(response, 200, { ok: true, path: path.relative(ROOT_DIR, targetPath) });
    } catch (error) {
      sendJson(response, 400, { ok: false, error: error.message });
    }
    return true;
  }

  return false;
}

async function handleHttp(request, response) {
  const urlPathname = requestPathname(request);

  if (await handleAuth(request, response, urlPathname)) {
    return;
  }

  if (!isAuthenticated(request)) {
    if (urlPathname.startsWith("/api/")) {
      sendJson(response, 401, { ok: false, error: "Authentication required." });
      return;
    }

    sendRedirect(response, "/login");
    return;
  }

  if (await handleApi(request, response, urlPathname)) {
    return;
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    sendJson(response, 405, { ok: false, error: "Method not allowed." });
    return;
  }

  const staticPath = resolveStaticPath(urlPathname);
  if (!staticPath || !isAllowedStaticPath(staticPath)) {
    sendText(response, 403, "Forbidden");
    return;
  }

  if (path.basename(staticPath) === "code_editor.html") {
    await resetLabFiles();
  }

  fs.stat(staticPath, (statError, stats) => {
    if (statError) {
      sendText(response, 404, "Not found");
      return;
    }

    if (stats.isDirectory()) {
      if (!urlPathname.endsWith("/")) {
        response.writeHead(308, { Location: `${urlPathname}/` });
        response.end();
        return;
      }
      sendText(response, 200, directoryListing(urlPathname, staticPath), "text/html; charset=utf-8");
      return;
    }

    const extension = path.extname(staticPath).toLowerCase();
    response.writeHead(200, {
      "Content-Type": CONTENT_TYPES[extension] || "application/octet-stream",
      "Content-Length": stats.size
    });

    if (request.method === "HEAD") {
      response.end();
      return;
    }

    fs.createReadStream(staticPath).pipe(response);
  });
}

function quotePowerShellString(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function terminalShell() {
  if (process.platform === "win32") {
    const labPath = quotePowerShellString(LABS_DIR);
    const initScript = [
      `$global:LabRoot = ${labPath}`,
      "Microsoft.PowerShell.Management\\Set-Location -LiteralPath $global:LabRoot",
      "function global:Resolve-LabLocation { param([string]$Path='.') if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq 'labs') { return $global:LabRoot } $candidate = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path)); $root = [System.IO.Path]::GetFullPath($global:LabRoot); if (-not ($candidate -eq $root -or $candidate.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar))) { throw 'Path is outside the labs directory.' } return $candidate }",
      "function global:Set-LabLocation { param([string]$Path='.') Microsoft.PowerShell.Management\\Set-Location -LiteralPath (Resolve-LabLocation $Path) }",
      "Remove-Item Alias:cd,Alias:chdir,Alias:sl,Alias:pushd,Alias:popd -Force -ErrorAction SilentlyContinue",
      "Set-Alias -Name cd -Value Set-LabLocation -Scope Global -Force",
      "Set-Alias -Name chdir -Value Set-LabLocation -Scope Global -Force",
      "Set-Alias -Name sl -Value Set-LabLocation -Scope Global -Force",
      "function global:pushd { Set-LabLocation @args }",
      "function global:popd { Microsoft.PowerShell.Utility\\Write-Host 'Directory stack is disabled in this lab terminal.' }",
      "function global:prompt { 'labs> ' }"
    ].join("; ");

    return {
      command: process.env.TERMINAL_SHELL || "powershell.exe",
      args: ["-NoLogo", "-NoProfile", "-NoExit", "-Command", initScript],
      cwd: LABS_DIR,
      label: "PowerShell"
    };
  }

  return {
    command: process.env.SHELL || "/bin/bash",
    args: [],
    cwd: LABS_DIR,
    label: "Shell"
  };
}

function sendTerminalMessage(socket, message) {
  if (socket.readyState === socket.OPEN) {
    socket.send(JSON.stringify(message));
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function terminalBlockReason(line) {
  const trimmed = line.trim();

  if (!trimmed || trimmed.startsWith("#")) {
    return "";
  }

  const normalized = trimmed.replace(/`/g, "").toLowerCase();
  const blockedCommandPattern = new RegExp(
    `(^|[\\s|;&])(?:${TERMINAL_BLOCKED_COMMANDS.map(escapeRegExp).join("|")})\\b`,
    "i"
  );

  if (/(^|[\s"'`])\.\.($|[\\/\s"'`])|[\\/]\.\.([\\/]|$)|\.\.[\\/]/.test(normalized)) {
    return "parent-directory paths are blocked; this terminal is restricted to labs.";
  }

  if (/(^|[\s"'`])[a-z]:[\\/]/i.test(normalized) || /(^|[\s"'`])~([\\/]|$)/.test(normalized) || /(^|[\s"'`])\/(?!\/)/.test(normalized)) {
    return "absolute filesystem paths are blocked; use files inside labs only.";
  }

  if (/(\$env:|\benv:|\b(?:dir|ls|get-childitem)\s+env:)/i.test(normalized)) {
    return "environment variable access is disabled in the lab terminal.";
  }

  if (/\bfile:\/\//i.test(normalized)) {
    return "file URLs are disabled in the lab terminal.";
  }

  if (blockedCommandPattern.test(normalized)) {
    return "opening external shells or desktop apps is disabled in the lab terminal.";
  }

  return "";
}

function createGuardedTerminalWriter(shellProcess, socket) {
  let currentLine = "";
  let inEscapeSequence = false;

  return function writeGuardedInput(data) {
    for (const char of data) {
      if (inEscapeSequence) {
        shellProcess.write(char);
        if (/[A-Za-z~]/.test(char)) {
          inEscapeSequence = false;
        }
        continue;
      }

      if (char === "\u001b") {
        inEscapeSequence = true;
        shellProcess.write(char);
        continue;
      }

      if (char === "\u0003") {
        currentLine = "";
        shellProcess.write(char);
        continue;
      }

      if (char === "\r" || char === "\n") {
        const blockReason = terminalBlockReason(currentLine);
        if (blockReason) {
          shellProcess.write("\u0003");
          sendTerminalMessage(socket, { type: "output", data: `\r\nBlocked: ${blockReason}\r\n` });
        } else {
          shellProcess.write(char === "\n" ? "\r" : char);
        }
        currentLine = "";
        continue;
      }

      if (char === "\u007f" || char === "\b") {
        currentLine = currentLine.slice(0, -1);
        shellProcess.write(char);
        continue;
      }

      if (char >= " ") {
        currentLine += char;
      }
      shellProcess.write(char);
    }
  };
}

function handleTerminalConnection(socket, request) {
  const query = new URL(request.url, `http://${request.headers.host || `${HOST}:${PORT}`}`).searchParams;
  const cols = Math.max(20, Math.min(240, Number(query.get("cols")) || 100));
  const rows = Math.max(8, Math.min(80, Number(query.get("rows")) || 30));
  const shell = terminalShell();
  const shellProcess = pty.spawn(shell.command, shell.args, {
    name: "xterm-color",
    cols,
    rows,
    cwd: shell.cwd,
    env: {
      ...process.env,
      TERM: "xterm-256color"
    }
  });
  const writeGuardedInput = createGuardedTerminalWriter(shellProcess, socket);

  sendTerminalMessage(socket, {
    type: "ready",
    shell: shell.label || shell.command,
    cwd: path.relative(ROOT_DIR, LABS_DIR) || "."
  });

  sendTerminalMessage(socket, {
    type: "output",
    data: "Terminal is restricted to the labs directory. Parent and absolute paths are blocked.\r\n"
  });

  shellProcess.onData((data) => {
    sendTerminalMessage(socket, { type: "output", data });
  });

  shellProcess.onExit(({ exitCode, signal }) => {
    sendTerminalMessage(socket, { type: "exit", exitCode, signal });
    socket.close();
  });

  socket.on("message", (rawMessage) => {
    let message;
    try {
      message = JSON.parse(String(rawMessage));
    } catch (error) {
      return;
    }

    if (message.type === "input" && typeof message.data === "string") {
      writeGuardedInput(message.data);
    }

    if (message.type === "run" && typeof message.command === "string") {
      const blockReason = terminalBlockReason(message.command);
      if (blockReason) {
        sendTerminalMessage(socket, { type: "output", data: `Blocked: ${blockReason}\r\n` });
        return;
      }

      shellProcess.write(`${message.command}\r`);
    }

    if (message.type === "resize") {
      const nextCols = Math.max(20, Math.min(240, Number(message.cols) || cols));
      const nextRows = Math.max(8, Math.min(80, Number(message.rows) || rows));
      shellProcess.resize(nextCols, nextRows);
    }
  });

  socket.on("close", () => {
    try {
      shellProcess.kill();
    } catch (error) {}
  });
}

const server = http.createServer((request, response) => {
  handleHttp(request, response).catch((error) => {
    sendJson(response, 500, { ok: false, error: error.message });
  });
});
const terminalServer = new WebSocketServer({ noServer: true });

server.on("upgrade", (request, socket, head) => {
  const urlPathname = requestPathname(request);

  if (urlPathname !== "/terminal" || !isAuthenticated(request)) {
    socket.destroy();
    return;
  }

  terminalServer.handleUpgrade(request, socket, head, (webSocket) => {
    handleTerminalConnection(webSocket, request);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`SOC lab editor running at http://${HOST}:${PORT}/code_editor.html`);
  console.log("Page access requires the configured lab password.");
  console.log("Terminal backend requires the same password session and starts in labs.");
});
