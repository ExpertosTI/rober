/**
 * EduCard Lab — motores criptográficos educativos (solo sandbox local).
 *
 * Método A (CVE): simula la lógica clásica de código estático
 * (concatenar → rellenar → 3DES educativo → decimalizar).
 *
 * Método B (CDT): alternativa más segura — código dinámico por ventana de tiempo (HMAC).
 *
 * NO conecta a servicios externos. NO usa datos reales de tarjetas.
 */

const crypto = require("crypto");
const { desEncryptBlock, desDecryptBlock } = require("./des_ecb");

function assertHex(value, label, expectedLen) {
  const v = String(value || "").replace(/\s+/g, "").toUpperCase();
  if (!/^[0-9A-F]+$/.test(v)) {
    throw new Error(`${label} debe ser hexadecimal`);
  }
  if (expectedLen && v.length !== expectedLen) {
    throw new Error(`${label} debe tener ${expectedLen} caracteres hex`);
  }
  return v;
}

function assertDigits(value, label, minLen, maxLen) {
  const v = String(value || "").replace(/\s+/g, "");
  if (!/^\d+$/.test(v)) {
    throw new Error(`${label} debe contener solo dígitos`);
  }
  if (v.length < minLen || v.length > maxLen) {
    throw new Error(`${label} debe tener entre ${minLen} y ${maxLen} dígitos`);
  }
  return v;
}

/**
 * Decimalización educativa: toma dígitos del hex; si faltan,
 * mapea A-F → 0-5 (patrón didáctico habitual en material académico).
 */
function decimalize(hex, digits = 3) {
  const upper = hex.toUpperCase();
  let out = "";
  for (const ch of upper) {
    if (/\d/.test(ch)) out += ch;
    if (out.length >= digits) return out.slice(0, digits);
  }
  const map = { A: "0", B: "1", C: "2", D: "3", E: "4", F: "5" };
  for (const ch of upper) {
    if (map[ch] !== undefined) out += map[ch];
    if (out.length >= digits) return out.slice(0, digits);
  }
  return (out + "000").slice(0, digits);
}

/**
 * Código de Verificación Estático (CVE) — análogo educativo del flujo clásico.
 */
function calcularCVE({ ncd, fechaDemo, codigoPerfil, claveA, claveB }) {
  const pan = assertDigits(ncd, "NCD", 12, 19);
  const exp = assertDigits(fechaDemo, "Fecha demo", 4, 4);
  const sc = assertDigits(codigoPerfil, "Código de perfil", 3, 3);
  const ka = assertHex(claveA, "Clave A", 16);
  const kb = assertHex(claveB, "Clave B", 16);

  const keyA = Buffer.from(ka, "hex");
  const keyB = Buffer.from(kb, "hex");

  // 1) Concatenar NCD + fecha + perfil
  const concat = pan + exp + sc;
  // 2) Rellenar a 32 nibbles (128 bits) con ceros
  const padded = (concat + "0".repeat(32)).slice(0, 32);
  const block1 = Buffer.from(padded.slice(0, 16), "hex");
  const block2 = Buffer.from(padded.slice(16, 32), "hex");

  // 3–7) Cadena 3DES educativa (EDE con KA/KB)
  const step3 = desEncryptBlock(keyA, block1);
  const step4 = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) step4[i] = step3[i] ^ block2[i];
  const step5 = desEncryptBlock(keyA, step4);
  const step6 = desDecryptBlock(keyB, step5);
  const step7 = desEncryptBlock(keyA, step6);

  const hexResult = step7.toString("hex").toUpperCase();
  const cve = decimalize(hexResult, 3);

  return {
    metodo: "CVE_ESTATICO",
    ncd: pan,
    fechaDemo: exp,
    codigoPerfil: sc,
    cve,
    traza: {
      concatenado: concat,
      bloqueHex: padded,
      resultadoHex: hexResult,
      nota: "Simulación educativa local. No es un servicio de pagos real.",
    },
  };
}

/**
 * Código Dinámico Temporizado (CDT) — alternativa más segura:
 * depende del secreto + ventana de tiempo, no es fijo en el plástico.
 */
function calcularCDT({ ncd, secretoEmisor, ventanaSegundos = 30, epochMs = Date.now() }) {
  const pan = assertDigits(ncd, "NCD", 12, 19);
  const secret = String(secretoEmisor || "");
  if (secret.length < 8) {
    throw new Error("El secreto del emisor demo debe tener al menos 8 caracteres");
  }
  const win = Number(ventanaSegundos) || 30;
  const counter = Math.floor(epochMs / 1000 / win);
  const payload = `${pan}|${counter}|EDUCARD-CDT-v1`;
  const hmac = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  // 6 dígitos dinámicos (más espacio → más difícil de adivinar que 3 fijos)
  const cdt = String(parseInt(hmac.slice(0, 8), 16) % 1_000_000).padStart(6, "0");
  const expiresIn = win - (Math.floor(epochMs / 1000) % win);

  return {
    metodo: "CDT_DINAMICO",
    ncd: pan,
    cdt,
    counter,
    ventanaSegundos: win,
    expiraEnSegundos: expiresIn,
    nota: "Válido solo en la ventana actual. Sin el secreto no se puede precomputar offline.",
  };
}

module.exports = { calcularCVE, calcularCDT, decimalize };