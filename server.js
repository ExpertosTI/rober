/**
 * Servidor sandbox local EduCard Lab (solo 127.0.0.1).
 * No hay llamadas a internet ni a calculadoras externas.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const { calcularCVE, calcularCDT } = require("./lib/crypto_demo");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT) || 8787;
const PUBLIC = path.join(__dirname, "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function sendJson(res, status, body) {
  const data = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(new Error("JSON inválido"));
      }
    });
    req.on("error", reject);
  });
}

function serveStatic(req, res) {
  let urlPath = req.url.split("?")[0];
  if (urlPath === "/") urlPath = "/index.html";
  const filePath = path.normalize(path.join(PUBLIC, urlPath));
  if (!filePath.startsWith(PUBLIC)) {
    res.writeHead(403);
    return res.end("Forbidden");
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404);
    return res.end("Not found");
  }
  const ext = path.extname(filePath);
  res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/api/health") {
      return sendJson(res, 200, {
        ok: true,
        sandbox: true,
        host: HOST,
        mensaje: "EduCard Lab — sandbox educativo local",
      });
    }

    if (req.method === "POST" && req.url === "/api/cve") {
      const body = await readBody(req);
      const result = calcularCVE(body);
      return sendJson(res, 200, result);
    }

    if (req.method === "POST" && req.url === "/api/cdt") {
      const body = await readBody(req);
      const result = calcularCDT(body);
      return sendJson(res, 200, result);
    }

    if (req.method === "GET" || req.method === "HEAD") {
      return serveStatic(req, res);
    }

    sendJson(res, 405, { error: "Método no permitido" });
  } catch (err) {
    sendJson(res, 400, { error: err.message || "Error" });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`\n[EduCard Lab] Sandbox local: http://${HOST}:${PORT}`);
  console.log("[EduCard Lab] Solo datos ficticios. Sin red externa.\n");
});
