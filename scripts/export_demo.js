/**
 * Exporta 15 demostraciones locales (CVE + CDT) a exports/resultados_demo.txt
 * Formato similar al script académico previo, con nombres demos.
 *
 * Uso: npm run export-demo
 */

const fs = require("fs");
const path = require("path");
const { calcularCVE, calcularCDT } = require("../lib/crypto_demo");

const ROOT = path.join(__dirname, "..");
const INPUT = path.join(ROOT, "data", "demo_cuentas_pipe.txt");
const OUTPUT = path.join(ROOT, "exports", "resultados_demo.txt");

// Claves demos fijas del laboratorio (NO son claves de un emisor real)
const CLAVE_A = "0022446688AACCEE";
const CLAVE_B = "FFDDBB9977553311";
const CODIGO_PERFIL = "000";
const SECRETO_CDT = "educard-demo-secreto-local-2026";

function parseLinea(linea) {
  const raw = linea.trim().replace(/\|+$/, "");
  if (!raw || raw.startsWith("#")) return null;
  if (raw.includes("|")) {
    const p = raw.split("|").map((x) => x.trim()).filter(Boolean);
    if (p.length >= 3) {
      // ncd|aaaa|mm|  o legacy ncd|mm|aaaa|
      if (/^\d{4}$/.test(p[1]) && /^\d{1,2}$/.test(p[2])) {
        const anio = p[1];
        const mm = p[2].padStart(2, "0");
        return { ncd: p[0], fechaDemo: anio.slice(-2) + mm, mes: mm, anio };
      }
      const mm = p[1].padStart(2, "0");
      const anio = p[2];
      return { ncd: p[0], fechaDemo: anio.slice(-2) + mm, mes: mm, anio };
    }
  }
  if (raw.includes(",")) {
    const [ncd, fechaDemo] = raw.split(",");
    return { ncd: ncd.trim(), fechaDemo: fechaDemo.trim() };
  }
  return null;
}

function cargarCuentas(archivo) {
  return fs
    .readFileSync(archivo, "utf8")
    .split(/\r?\n/)
    .map(parseLinea)
    .filter(Boolean);
}

function main() {
  const cuentas = cargarCuentas(INPUT).slice(0, 15);
  const lineas = [];
  lineas.push("# EduCard Lab — exportación sandbox educativa");
  lineas.push(`# Generado: ${new Date().toISOString()}`);
  lineas.push("# Formato CVE: ncd,fechaDemo,codigoPerfil,cve");
  lineas.push("# Formato CDT: ncd,counter,cdt,expiraEnSegundos");
  lineas.push("# --- CVE_ESTATICO ---");

  for (const c of cuentas) {
    const r = calcularCVE({
      ncd: c.ncd,
      fechaDemo: c.fechaDemo,
      codigoPerfil: CODIGO_PERFIL,
      claveA: CLAVE_A,
      claveB: CLAVE_B,
    });
    lineas.push(`${r.ncd},${r.fechaDemo},${r.codigoPerfil},${r.cve}`);
  }

  lineas.push("# --- CDT_DINAMICO ---");
  for (const c of cuentas) {
    const r = calcularCDT({
      ncd: c.ncd,
      secretoEmisor: SECRETO_CDT,
      ventanaSegundos: 30,
    });
    lineas.push(`${r.ncd},${r.counter},${r.cdt},${r.expiraEnSegundos}`);
  }

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, lineas.join("\n") + "\n", "utf8");
  console.log(`[+] ${cuentas.length} demos exportadas → ${OUTPUT}`);
}

main();