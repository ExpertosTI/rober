/**
 * EduCard Lab — motor de cálculo EN EL NAVEGADOR (client-side).
 * Algoritmo A: flujo clásico educativo 3DES (DES-EDE) + decimalización → CVE
 * Algoritmo B: HMAC-SHA256 por ventana de tiempo → CDT
 */
(function (global) {
  "use strict";

  const PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
  const PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
  const IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
  const FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
  const E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
  const P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
  const SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
  const S = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
  ];

  function permute(bits, table) {
    return table.map((i) => bits[i - 1]);
  }
  function bytesToBits(buf) {
    const bits = [];
    for (let i = 0; i < buf.length; i++) {
      for (let b = 7; b >= 0; b--) bits.push((buf[i] >> b) & 1);
    }
    return bits;
  }
  function bitsToBytes(bits) {
    const out = new Uint8Array(bits.length / 8);
    for (let i = 0; i < out.length; i++) {
      let v = 0;
      for (let b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
      out[i] = v;
    }
    return out;
  }
  function leftRotate(arr, n) {
    return arr.slice(n).concat(arr.slice(0, n));
  }
  function keySchedule(key8) {
    let keyBits = permute(bytesToBits(key8), PC1);
    let c = keyBits.slice(0, 28);
    let d = keyBits.slice(28);
    const subkeys = [];
    for (let i = 0; i < 16; i++) {
      c = leftRotate(c, SHIFTS[i]);
      d = leftRotate(d, SHIFTS[i]);
      subkeys.push(permute(c.concat(d), PC2));
    }
    return subkeys;
  }
  function f(r, sk) {
    const expanded = permute(r, E);
    const xored = expanded.map((bit, i) => bit ^ sk[i]);
    const sOut = [];
    for (let i = 0; i < 8; i++) {
      const chunk = xored.slice(i * 6, i * 6 + 6);
      const row = (chunk[0] << 1) | chunk[5];
      const col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4];
      const val = S[i][row * 16 + col];
      for (let b = 3; b >= 0; b--) sOut.push((val >> b) & 1);
    }
    return permute(sOut, P);
  }
  function desBlock(block8, key8, decrypt) {
    let subkeys = keySchedule(key8);
    if (decrypt) subkeys = subkeys.slice().reverse();
    let bits = permute(bytesToBits(block8), IP);
    let l = bits.slice(0, 32);
    let r = bits.slice(32);
    for (let i = 0; i < 16; i++) {
      const prevL = l;
      l = r;
      const fr = f(r, subkeys[i]);
      r = prevL.map((bit, idx) => bit ^ fr[idx]);
    }
    return bitsToBytes(permute(r.concat(l), FP));
  }
  function desEncrypt(key8, block8) { return desBlock(block8, key8, false); }
  function desDecrypt(key8, block8) { return desBlock(block8, key8, true); }

  function hexToBytes(hex) {
    const h = hex.replace(/\s+/g, "").toUpperCase();
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  function bytesToHex(buf) {
    return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }
  function assertHex(value, label, len) {
    const v = String(value || "").replace(/\s+/g, "").toUpperCase();
    if (!/^[0-9A-F]+$/.test(v)) throw new Error(label + " debe ser hexadecimal");
    if (len && v.length !== len) throw new Error(label + " debe tener " + len + " caracteres hex");
    return v;
  }
  function assertDigits(value, label, minLen, maxLen) {
    const v = String(value || "").replace(/\s+/g, "");
    if (!/^\d+$/.test(v)) throw new Error(label + " debe contener solo dígitos");
    if (v.length < minLen || v.length > maxLen) throw new Error(label + " longitud inválida");
    return v;
  }
  function decimalize(hex, digits) {
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
   * ALGORITMO CVE (educativo, análogo al flujo clásico de industria):
   * 1 concat NCD+fecha+perfil
   * 2 pad a 32 hex
   * 3 DES(KA, block1)
   * 4 XOR block2
   * 5 DES(KA)
   * 6 DES-1(KB)
   * 7 DES(KA)
   * 8 decimalizar → 3 dígitos
   */
  function calcularCVE({ ncd, fechaDemo, codigoPerfil, claveA, claveB }) {
    const pan = assertDigits(ncd, "NCD", 12, 19);
    const exp = assertDigits(fechaDemo, "Fecha demo", 4, 4);
    const sc = assertDigits(codigoPerfil, "Código de perfil", 3, 3);
    const ka = assertHex(claveA, "Clave A", 16);
    const kb = assertHex(claveB, "Clave B", 16);
    const keyA = hexToBytes(ka);
    const keyB = hexToBytes(kb);
    const concat = pan + exp + sc;
    const padded = (concat + "0".repeat(32)).slice(0, 32);
    const block1 = hexToBytes(padded.slice(0, 16));
    const block2 = hexToBytes(padded.slice(16, 32));
    const step3 = desEncrypt(keyA, block1);
    const step4 = new Uint8Array(8);
    for (let i = 0; i < 8; i++) step4[i] = step3[i] ^ block2[i];
    const step5 = desEncrypt(keyA, step4);
    const step6 = desDecrypt(keyB, step5);
    const step7 = desEncrypt(keyA, step6);
    const resultadoHex = bytesToHex(step7);
    const cve = decimalize(resultadoHex, 3);
    return {
      metodo: "CVE_ESTATICO",
      motor: "navegador",
      algoritmo: "DES-EDE educativo + decimalizacion",
      ncd: pan,
      fechaDemo: exp,
      codigoPerfil: sc,
      cve,
      traza: { concatenado: concat, bloqueHex: padded, resultadoHex },
    };
  }

  async function calcularCDT({ ncd, secretoEmisor, ventanaSegundos = 30, epochMs = Date.now() }) {
    const pan = assertDigits(ncd, "NCD", 12, 19);
    const secret = String(secretoEmisor || "");
    if (secret.length < 8) throw new Error("Secreto demo demasiado corto");
    const win = Number(ventanaSegundos) || 30;
    const counter = Math.floor(epochMs / 1000 / win);
    const payload = `${pan}|${counter}|EDUCARD-CDT-v1`;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
    const hex = bytesToHex(new Uint8Array(sig));
    const cdt = String(parseInt(hex.slice(0, 8), 16) % 1_000_000).padStart(6, "0");
    const expiraEnSegundos = win - (Math.floor(epochMs / 1000) % win);
    return {
      metodo: "CDT_DINAMICO",
      motor: "navegador",
      algoritmo: "HMAC-SHA256 + ventana temporal",
      ncd: pan,
      cdt,
      counter,
      ventanaSegundos: win,
      expiraEnSegundos,
    };
  }

  /** Valores de referencia del laboratorio (comportamiento 3DES / CED = CVKA‖CVKB). */
  const DEFAULTS = {
    claveA: "0022446688AACCEE",
    claveB: "FFDDBB9977553311",
    cedCompleta: "0022446688AACCEEFFDDBB9977553311",
    codigoPerfil: "101",
    secretoCdt: "educard-demo-secreto-local-2026",
  };

  /**
   * Estructura de datos de práctica:
   *   ncd|aaaa|mm|     → fecha interna AAMM (YYMM)  [año primero, mes segundo]
   *   ncd,aamm
   *   ncd,aaaa,mm
   *   (legacy) ncd|mm|aaaa|
   */
  function parseLineaCuenta(linea) {
    const raw = String(linea || "").trim().replace(/\|+$/, "");
    if (!raw || raw.startsWith("#")) return null;

    if (raw.includes("|")) {
      const p = raw.split("|").map((x) => x.trim()).filter(Boolean);
      // ncd|aaaa|mm|
      if (p.length >= 3 && /^\d{12,19}$/.test(p[0]) && /^\d{4}$/.test(p[1]) && /^\d{1,2}$/.test(p[2])) {
        const anio = p[1];
        const mm = p[2].padStart(2, "0");
        const yy = anio.slice(-2);
        return {
          ncd: p[0],
          mes: mm,
          anio,
          fechaDemo: yy + mm,
          crudo: `${p[0]}|${anio}|${mm}|`,
        };
      }
      // legacy ncd|mm|aaaa|
      if (p.length >= 3 && /^\d{12,19}$/.test(p[0]) && /^\d{1,2}$/.test(p[1]) && /^\d{4}$/.test(p[2])) {
        const mm = p[1].padStart(2, "0");
        const anio = p[2];
        const yy = anio.slice(-2);
        return {
          ncd: p[0],
          mes: mm,
          anio,
          fechaDemo: yy + mm,
          crudo: `${p[0]}|${anio}|${mm}|`,
        };
      }
      return null;
    }

    const parts = raw.split(/[,\s;]+/).filter(Boolean);
    // ncd,aaaa,mm
    if (parts.length >= 3 && /^\d{12,19}$/.test(parts[0]) && /^\d{4}$/.test(parts[1]) && /^\d{1,2}$/.test(parts[2])) {
      const anio = parts[1];
      const mm = parts[2].padStart(2, "0");
      const yy = anio.slice(-2);
      return {
        ncd: parts[0],
        mes: mm,
        anio,
        fechaDemo: yy + mm,
        crudo: `${parts[0]}|${anio}|${mm}|`,
      };
    }
    // legacy ncd,mm,aaaa
    if (parts.length >= 3 && /^\d{12,19}$/.test(parts[0]) && /^\d{1,2}$/.test(parts[1]) && /^\d{4}$/.test(parts[2])) {
      const mm = parts[1].padStart(2, "0");
      const anio = parts[2];
      const yy = anio.slice(-2);
      return {
        ncd: parts[0],
        mes: mm,
        anio,
        fechaDemo: yy + mm,
        crudo: `${parts[0]}|${anio}|${mm}|`,
      };
    }
    if (parts.length >= 2 && /^\d{12,19}$/.test(parts[0]) && /^\d{4}$/.test(parts[1])) {
      const aamm = parts[1];
      return {
        ncd: parts[0],
        mes: aamm.slice(2, 4),
        anio: "20" + aamm.slice(0, 2),
        fechaDemo: aamm,
        crudo: `${parts[0]}|20${aamm.slice(0, 2)}|${aamm.slice(2, 4)}|`,
      };
    }
    if (parts.length >= 1 && /^\d{12,19}$/.test(parts[0])) {
      return {
        ncd: parts[0],
        mes: "08",
        anio: "2031",
        fechaDemo: "3108",
        crudo: `${parts[0]}|2031|08|`,
      };
    }
    return null;
  }

  function parsePaquete(texto) {
    const lineas = String(texto).split(/\r?\n/);
    const meta = {
      claveA: DEFAULTS.claveA,
      claveB: DEFAULTS.claveB,
      codigoPerfil: DEFAULTS.codigoPerfil,
      secretoCdt: DEFAULTS.secretoCdt,
    };
    const cuentas = [];
    let enDatos = false;
    for (const raw of lineas) {
      const linea = raw.trim();
      if (!linea) continue;
      if (linea.startsWith("#")) {
        if (linea.toUpperCase().includes("BEGIN_DATOS")) enDatos = true;
        if (linea.toUpperCase().includes("END_DATOS")) enDatos = false;
        continue;
      }
      if (linea.startsWith("CLAVE_A=")) meta.claveA = linea.slice(8).trim();
      else if (linea.startsWith("CLAVE_B=")) meta.claveB = linea.slice(8).trim();
      else if (linea.startsWith("PERFIL=")) meta.codigoPerfil = linea.slice(7).trim();
      else if (linea.startsWith("SECRETO_CDT=")) meta.secretoCdt = linea.slice(12).trim();
      else if (enDatos || linea.includes("|") || /^\d{12,19}[,|]/.test(linea)) {
        const c = parseLineaCuenta(linea);
        if (c) cuentas.push(c);
      }
    }
    return { meta, cuentas };
  }

  function splitCed(ced32) {
    const h = assertHex(ced32, "CED completa", 32);
    return { claveA: h.slice(0, 16), claveB: h.slice(16, 32), cedCompleta: h };
  }

  /**
   * Análisis educativo de ciberseguridad (NO es un ataque a sistemas reales).
   * Mide velocidad local, espacio de salida y resistencia teórica a adivinanza.
   */
  function analizarFuerzaCVE() {
    const espacioSalida = 1000; // 000–999
    const bitsSalida = Math.log2(espacioSalida);
    const bitsClaveDobleDES = 112; // 2-key 3DES efectivo aproximado (educativo)
    return {
      algoritmo: "DES-EDE + decimalización → CVE 3 dígitos",
      espacioSalida,
      bitsSalidaAprox: Number(bitsSalida.toFixed(2)),
      bitsClaveAprox: bitsClaveDobleDES,
      veredictoSalida:
        "La salida de 3 dígitos es débil frente a adivinanza online (~1000 intentos). La fuerza real depende de proteger la CED/CVK (HSM), no del CVE impreso.",
      mejoras: [
        "No exponer la CED/CVK fuera de un HSM",
        "Rate-limit + lockout en verificación online",
        "Preferir códigos dinámicos (CDT/dCVV) o 3-D Secure",
        "No almacenar el CVE tras autorización (PCI)",
      ],
    };
  }

  function analizarFuerzaCDT(ventanaSegundos = 30) {
    const espacioSalida = 1_000_000;
    return {
      algoritmo: "HMAC-SHA256 + ventana temporal → CDT 6 dígitos",
      espacioSalida,
      bitsSalidaAprox: Number(Math.log2(espacioSalida).toFixed(2)),
      ventanaSegundos,
      veredictoSalida:
        "Más resistente: rota cada ventana, espacio 1e6 y requiere secreto + tiempo alineado. Aún así conviene rate-limit.",
      mejoras: [
        "Ventanas cortas (30s) + tolerancia ±1",
        "Secreto largo aleatorio en HSM/KMS",
        "Binding a dispositivo o challenge adicional",
      ],
    };
  }

  /**
   * Benchmark local: cuántos CVE/s procesa este navegador.
   * Usa NCD sintéticos ficticios; no prueba sistemas ajenos.
   */
  function benchmarkCVE({ claveA, claveB, codigoPerfil, iteraciones = 200 } = {}) {
    const ka = claveA || DEFAULTS.claveA;
    const kb = claveB || DEFAULTS.claveB;
    const sc = codigoPerfil || DEFAULTS.codigoPerfil;
    const n = Math.max(20, Math.min(5000, Number(iteraciones) || 200));
    const t0 = performance.now();
    for (let i = 0; i < n; i++) {
      const ncd = String(4000000000000000 + (i % 900000000000000)).padStart(16, "0").slice(0, 16);
      const fecha = String(2500 + (i % 100)).padStart(4, "0");
      calcularCVE({ ncd, fechaDemo: fecha, codigoPerfil: sc, claveA: ka, claveB: kb });
    }
    const ms = performance.now() - t0;
    const opsPorSeg = ms > 0 ? (n / ms) * 1000 : n;
    return {
      iteraciones: n,
      ms: Number(ms.toFixed(2)),
      opsPorSeg: Number(opsPorSeg.toFixed(1)),
      nota: "Velocidad local del motor JS (educativa). No mide un emisor real ni un HSM.",
    };
  }

  /**
   * Simulación educativa de adivinanza online del CVE (espacio 1000),
   * midiendo tiempo local. No conecta a ningún servicio.
   */
  function simularAdivinanzaCVE({ ncd, fechaDemo, codigoPerfil, claveA, claveB, maxIntentos = 1000 } = {}) {
    const objetivo = calcularCVE({ ncd, fechaDemo, codigoPerfil, claveA, claveB }).cve;
    const t0 = performance.now();
    let encontrados = 0;
    let intentos = 0;
    const limite = Math.min(1000, Math.max(1, Number(maxIntentos) || 1000));
    for (let g = 0; g < limite; g++) {
      intentos++;
      const guess = String(g).padStart(3, "0");
      if (guess === objetivo) {
        encontrados++;
        break;
      }
    }
    const ms = performance.now() - t0;
    return {
      cveObjetivo: objetivo,
      intentosHastaAcierto: intentos,
      ms: Number(ms.toFixed(3)),
      espacio: 1000,
      conclusion:
        encontrados > 0
          ? "En sandbox local el CVE de 3 dígitos se agota en ≤1000 pruebas. En producción debe haber rate-limit/HSM; el CDT mitiga este riesgo."
          : "No se alcanzó el objetivo en el límite (configuración incompleta).",
    };
  }

  function parsePegado(texto) {
    const cuentas = [];
    for (const raw of String(texto).split(/\r?\n/)) {
      const c = parseLineaCuenta(raw);
      if (c) cuentas.push(c);
    }
    return cuentas;
  }

  global.EduCardMotor = {
    calcularCVE,
    calcularCDT,
    parsePaquete,
    parsePegado,
    parseLineaCuenta,
    splitCed,
    DEFAULTS,
    analizarFuerzaCVE,
    analizarFuerzaCDT,
    benchmarkCVE,
    simularAdivinanzaCVE,
    ALGORITMO_CVE: "Triple DES (DES-EDE / CED=CVKA||CVKB) + decimalización → 3 dígitos",
    ALGORITMO_CDT: "HMAC-SHA256 + ventana temporal → 6 dígitos",
  };
})(typeof window !== "undefined" ? window : globalThis);
