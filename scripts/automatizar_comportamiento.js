/**
 * Automatiza SOLO el comportamiento del laboratorio local EduCard Lab.
 *
 * Flujo (mismo patrón educativo que un script de formulario):
 *   1) cargar cuentas demo
 *   2) rellenar parámetros
 *   3) "enviar" cálculo al sandbox local
 *   4) leer resultado
 *   5) exportar TXT
 *
 * Destino fijo: http://127.0.0.1:8787  (nunca sitios externos)
 *
 * Uso: npm run automatizar
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const INPUT = path.join(ROOT, "data", "demo_cuentas_pipe.txt");
const OUTPUT = path.join(ROOT, "exports", "resultados_comportamiento.txt");
const BASE = "http://127.0.0.1:8787";

const CLAVE_A = "0022446688AACCEE";
const CLAVE_B = "FFDDBB9977553311";
const CODIGO_PERFIL = "101";
const SECRETO_CDT = "educard-demo-secreto-local-2026";
const PAUSA_MS = 200;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** ncd|mm|aaaa| → AAMM ; también soporta ncd,aamm */
function parseLinea(linea) {
  const raw = linea.trim().replace(/\|+$/, "");
  if (!raw || raw.startsWith("#")) return null;
  if (raw.includes("|")) {
    const p = raw.split("|").map((x) => x.trim()).filter(Boolean);
    if (p.length >= 3) {
      const mm = p[1].padStart(2, "0");
      const yy = p[2].slice(-2);
      return { ncd: p[0], fechaDemo: yy + mm, mes: mm, anio: p[2] };
    }
  }
  if (raw.includes(",")) {
    const [ncd, fechaDemo] = raw.split(",");
    return { ncd: ncd.trim(), fechaDemo: fechaDemo.trim() };
  }
  return null;
}

function cargarCuentas(archivo) {
  if (!fs.existsSync(archivo)) {
    throw new Error(`No existe ${archivo}`);
  }
  return fs
    .readFileSync(archivo, "utf8")
    .split(/\r?\n/)
    .map(parseLinea)
    .filter(Boolean)
    .map((c) => ({
      ...c,
      codigoPerfil: CODIGO_PERFIL,
      claveA: CLAVE_A,
      claveB: CLAVE_B,
      secretoEmisor: SECRETO_CDT,
    }))
    .slice(0, 15);
}

async function postJson(ruta, body) {
  const res = await fetch(`${BASE}${ruta}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function main() {
  console.log("[*] EduCard Lab — automatización de comportamiento (solo sandbox local)");
  console.log(`[*] Destino: ${BASE}`);

  const health = await fetch(`${BASE}/api/health`).then((r) => r.json());
  if (!health.ok || !health.sandbox) {
    throw new Error("El servidor local no responde como sandbox educativo");
  }
  console.log(`[+] Health OK: ${health.mensaje}`);

  const cuentas = cargarCuentas(INPUT);
  console.log(`[*] Procesando ${cuentas.length} cuentas demo...\n`);

  const lineas = [];
  lineas.push("# EduCard Lab — resultados de comportamiento automatizado");
  lineas.push(`# Generado: ${new Date().toISOString()}`);
  lineas.push(`# Destino: ${BASE} (sandbox local)`);
  lineas.push("# Formato CVE: ncd,fechaDemo,codigoPerfil,cve");
  lineas.push("# Formato CDT: ncd,counter,cdt,expiraEnSegundos");
  lineas.push("# --- CVE_ESTATICO (comportamiento método A) ---");

  for (let i = 0; i < cuentas.length; i++) {
    const c = cuentas[i];
    process.stdout.write(`[${i + 1}/${cuentas.length}] CVE NCD=${c.ncd} ... `);
    try {
      // Comportamiento: rellenar → enviar → leer resultado
      const payload = {
        ncd: c.ncd,
        fechaDemo: c.fechaDemo,
        codigoPerfil: c.codigoPerfil,
        claveA: c.claveA,
        claveB: c.claveB,
      };
      const r = await postJson("/api/cve", payload);
      lineas.push(`${r.ncd},${r.fechaDemo},${r.codigoPerfil},${r.cve}`);
      console.log(`OK CVE=${r.cve}`);
    } catch (e) {
      lineas.push(`${c.ncd},${c.fechaDemo},${c.codigoPerfil},ERROR`);
      console.log(`ERROR ${e.message}`);
    }
    await sleep(PAUSA_MS);
  }

  lineas.push("# --- CDT_DINAMICO (comportamiento método B) ---");
  for (let i = 0; i < cuentas.length; i++) {
    const c = cuentas[i];
    process.stdout.write(`[${i + 1}/${cuentas.length}] CDT NCD=${c.ncd} ... `);
    try {
      const r = await postJson("/api/cdt", {
        ncd: c.ncd,
        secretoEmisor: c.secretoEmisor,
        ventanaSegundos: 30,
      });
      lineas.push(`${r.ncd},${r.counter},${r.cdt},${r.expiraEnSegundos}`);
      console.log(`OK CDT=${r.cdt}`);
    } catch (e) {
      lineas.push(`${c.ncd},,,ERROR`);
      console.log(`ERROR ${e.message}`);
    }
    await sleep(PAUSA_MS);
  }

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, lineas.join("\n") + "\n", "utf8");
  console.log(`\n[+] Comportamiento exportado → ${OUTPUT}`);
}

main().catch((err) => {
  console.error(`[-] ${err.message}`);
  console.error("[-] Asegura: npm start  (servidor en 127.0.0.1:8787)");
  process.exit(1);
});
