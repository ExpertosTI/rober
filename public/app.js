(() => {
  const motor = window.EduCardMotor;
  if (!motor) {
    console.error("EduCardMotor no cargó. Revisa /motor.js");
    return;
  }

  const D = motor.DEFAULTS;

  const tabs = document.querySelectorAll(".tab");
  const panels = {
    cve: document.getElementById("panel-cve"),
    cdt: document.getElementById("panel-cdt"),
    practica: document.getElementById("panel-practica"),
    lab: document.getElementById("panel-lab"),
    mapa: document.getElementById("panel-mapa"),
  };

  let paqueteActual = null;
  let ultimoExport = "";
  let ultimoInforme = "";

  // Defaults de comportamiento (CVKA‖CVKB)
  document.getElementById("cve-ka").value = D.claveA;
  document.getElementById("cve-kb").value = D.claveB;
  document.getElementById("cve-ced").value = D.cedCompleta;
  document.getElementById("cve-perfil").value = D.codigoPerfil;
  document.getElementById("cdt-secreto").value = D.secretoCdt;

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const id = tab.dataset.tab;
      tabs.forEach((t) => {
        t.classList.toggle("active", t === tab);
        t.setAttribute("aria-selected", t === tab ? "true" : "false");
      });
      Object.entries(panels).forEach(([key, el]) => {
        if (!el) return;
        const on = key === id;
        el.classList.toggle("active", on);
        el.hidden = !on;
      });
    });
  });

  function show(el, html) {
    el.hidden = false;
    el.innerHTML = html;
  }

  function keysFromForm() {
    const ced = document.getElementById("cve-ced").value.trim();
    if (ced.length === 32) {
      try {
        const parts = motor.splitCed(ced);
        document.getElementById("cve-ka").value = parts.claveA;
        document.getElementById("cve-kb").value = parts.claveB;
        return parts;
      } catch (_) {
        /* fall through */
      }
    }
    return {
      claveA: document.getElementById("cve-ka").value.trim(),
      claveB: document.getElementById("cve-kb").value.trim(),
      cedCompleta:
        document.getElementById("cve-ka").value.trim() +
        document.getElementById("cve-kb").value.trim(),
    };
  }

  document.getElementById("cve-ced").addEventListener("change", () => {
    try {
      keysFromForm();
    } catch (e) {
      /* ignore while typing */
    }
  });

  function extractRoadmap(texto) {
    return texto
      .split(/\r?\n/)
      .filter(
        (l) =>
          /^#\s*R\d/.test(l.trim()) ||
          /^#\s*--- ALGORITMO/.test(l.trim()) ||
          /^#\s*ALGORITMO_/.test(l.trim())
      )
      .map((l) => l.replace(/^#\s?/, ""))
      .join("\n");
  }

  function activarPaquete(texto, origen) {
    paqueteActual = motor.parsePaquete(texto);
    const roadmap = extractRoadmap(texto) || "Roadmap no encontrado en el archivo.";
    document.getElementById("pkg-roadmap").textContent =
      `Origen: ${origen}\nCuentas: ${paqueteActual.cuentas.length}\n` +
      `Algoritmo A: ${motor.ALGORITMO_CVE}\nAlgoritmo B: ${motor.ALGORITMO_CDT}\n\n` +
      roadmap;
    document.getElementById("pkg-run").disabled = paqueteActual.cuentas.length === 0;
    document.getElementById("pkg-download").disabled = true;
    document.getElementById("out-practica").hidden = true;

    document.getElementById("cve-ka").value = paqueteActual.meta.claveA;
    document.getElementById("cve-kb").value = paqueteActual.meta.claveB;
    document.getElementById("cve-ced").value =
      paqueteActual.meta.claveA + paqueteActual.meta.claveB;
    document.getElementById("cve-perfil").value = paqueteActual.meta.codigoPerfil;
    document.getElementById("cdt-secreto").value = paqueteActual.meta.secretoCdt;
    if (paqueteActual.cuentas[0]) {
      document.getElementById("cve-ncd").value = paqueteActual.cuentas[0].ncd;
      document.getElementById("cve-fecha").value = paqueteActual.cuentas[0].fechaDemo;
      document.getElementById("cdt-ncd").value = paqueteActual.cuentas[0].ncd;
    }
  }

  document.getElementById("form-cve").addEventListener("submit", (e) => {
    e.preventDefault();
    const out = document.getElementById("out-cve");
    try {
      const keys = keysFromForm();
      const data = motor.calcularCVE({
        ncd: document.getElementById("cve-ncd").value,
        fechaDemo: document.getElementById("cve-fecha").value,
        codigoPerfil: document.getElementById("cve-perfil").value,
        claveA: keys.claveA,
        claveB: keys.claveB,
      });
      show(
        out,
        `<span class="warn">Motor navegador · Triple DES (CED=${keys.cedCompleta})</span>\n` +
          `CVE = <span class="big">${data.cve}</span>` +
          `NCD: ${data.ncd}\n` +
          `Fecha: ${data.fechaDemo} · Perfil: ${data.codigoPerfil}\n` +
          `Bloque: ${data.traza.bloqueHex}\n` +
          `Hex: ${data.traza.resultadoHex}`
      );
    } catch (err) {
      show(out, `<span class="warn">Error: ${err.message}</span>`);
    }
  });

  document.getElementById("form-cdt").addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = document.getElementById("out-cdt");
    try {
      const data = await motor.calcularCDT({
        ncd: document.getElementById("cdt-ncd").value,
        secretoEmisor: document.getElementById("cdt-secreto").value,
        ventanaSegundos: Number(document.getElementById("cdt-ventana").value),
      });
      show(
        out,
        `<span class="warn">Motor navegador · ${data.algoritmo}</span>\n` +
          `CDT = <span class="big">${data.cdt}</span>` +
          `NCD: ${data.ncd}\n` +
          `Ventana #${data.counter} · expira en ${data.expiraEnSegundos}s`
      );
    } catch (err) {
      show(out, `<span class="warn">Error: ${err.message}</span>`);
    }
  });

  document.getElementById("pkg-file").addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    activarPaquete(await file.text(), file.name);
  });

  document.getElementById("pkg-load-default").addEventListener("click", async () => {
    const res = await fetch("/paquete_practica.txt");
    if (!res.ok) throw new Error("No se pudo cargar paquete_practica.txt");
    activarPaquete(await res.text(), "paquete_practica.txt (demo)");
  });

  document.getElementById("pkg-run").addEventListener("click", async () => {
    if (!paqueteActual) return;
    const out = document.getElementById("out-practica");
    const { meta, cuentas } = paqueteActual;
    const lineas = [];
    lineas.push("# Resultados práctica — motor navegador EduCard Lab");
    lineas.push(`# Generado: ${new Date().toISOString()}`);
    lineas.push(`# CED: ${meta.claveA}${meta.claveB}`);
    lineas.push(`# Algoritmo A: ${motor.ALGORITMO_CVE}`);
    lineas.push(`# Algoritmo B: ${motor.ALGORITMO_CDT}`);
    lineas.push("# --- CVE_ESTATICO ---");

    let html = `<span class="warn">Procesando ${cuentas.length} demos en el navegador...</span>\n`;
    show(out, html);

    for (let i = 0; i < cuentas.length; i++) {
      const c = cuentas[i];
      const r = motor.calcularCVE({
        ncd: c.ncd,
        fechaDemo: c.fechaDemo,
        codigoPerfil: meta.codigoPerfil,
        claveA: meta.claveA,
        claveB: meta.claveB,
      });
      lineas.push(`${r.ncd},${r.fechaDemo},${r.codigoPerfil},${r.cve}`);
      html += `[${i + 1}/${cuentas.length}] CVE ${r.ncd} → ${r.cve}\n`;
      show(out, html);
      await new Promise((r0) => setTimeout(r0, 40));
    }

    lineas.push("# --- CDT_DINAMICO ---");
    html += "\n";
    for (let i = 0; i < cuentas.length; i++) {
      const c = cuentas[i];
      const r = await motor.calcularCDT({
        ncd: c.ncd,
        secretoEmisor: meta.secretoCdt,
        ventanaSegundos: 30,
      });
      lineas.push(`${r.ncd},${r.counter},${r.cdt},${r.expiraEnSegundos}`);
      html += `[${i + 1}/${cuentas.length}] CDT ${r.ncd} → ${r.cdt}\n`;
      show(out, html);
      await new Promise((r0) => setTimeout(r0, 40));
    }

    ultimoExport = lineas.join("\n") + "\n";
    document.getElementById("pkg-download").disabled = false;
    html += `\n<span class="warn">Listo. Puedes descargar resultados_practica.txt</span>`;
    show(out, html);
  });

  document.getElementById("pkg-download").addEventListener("click", () => {
    if (!ultimoExport) return;
    descargar(ultimoExport, "resultados_practica.txt");
  });

  function descargar(texto, nombre) {
    const blob = new Blob([texto], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = nombre;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function paintMetrics(cards) {
    const box = document.getElementById("lab-metrics");
    box.hidden = false;
    box.innerHTML = cards
      .map(
        (c) =>
          `<article class="metric"><span class="metric-k">${c.k}</span><span class="metric-v">${c.v}</span><span class="metric-h">${c.h || ""}</span></article>`
      )
      .join("");
  }

  document.getElementById("lab-fill-demo").addEventListener("click", async () => {
    const res = await fetch("/paquete_practica.txt");
    const texto = await res.text();
    const pkg = motor.parsePaquete(texto);
    document.getElementById("lab-paste").value = pkg.cuentas
      .map((c) => c.crudo || `${c.ncd}|${c.mes || "08"}|${c.anio || "2031"}|`)
      .join("\n");
  });

  document.getElementById("lab-run-batch").addEventListener("click", async () => {
    const out = document.getElementById("out-lab");
    const keys = keysFromForm();
    const perfil = document.getElementById("cve-perfil").value;
    const cuentas = motor.parsePegado(document.getElementById("lab-paste").value);
    if (!cuentas.length) {
      show(out, `<span class="warn">Pega al menos una línea ncd,fecha</span>`);
      return;
    }

    const t0 = performance.now();
    const lineas = [];
    lineas.push("# EduCard Lab — lote pegado (motor navegador)");
    lineas.push(`# Generado: ${new Date().toISOString()}`);
    lineas.push(`# CED/CVK: ${keys.cedCompleta}`);
    lineas.push(`# Algoritmo: ${motor.ALGORITMO_CVE}`);
      lineas.push("# ncd|aaaa|mm|aamm|perfil|cve");

    let html = "";
    for (let i = 0; i < cuentas.length; i++) {
      const c = cuentas[i];
      const r = motor.calcularCVE({
        ncd: c.ncd,
        fechaDemo: c.fechaDemo,
        codigoPerfil: perfil,
        claveA: keys.claveA,
        claveB: keys.claveB,
      });
      const mm = c.mes || r.fechaDemo.slice(2, 4);
      const anio = c.anio || "20" + r.fechaDemo.slice(0, 2);
      lineas.push(`${r.ncd}|${anio}|${mm}|${r.fechaDemo}|${r.codigoPerfil}|${r.cve}`);
      html += `[${i + 1}/${cuentas.length}] ${r.ncd}|${anio}|${mm}| → CVE ${r.cve}\n`;
    }
    const ms = performance.now() - t0;
    lineas.push(`# ms_total=${ms.toFixed(2)} ops=${cuentas.length}`);

    ultimoInforme = lineas.join("\n") + "\n";
    document.getElementById("lab-download").disabled = false;
    paintMetrics([
      { k: "Cuentas", v: String(cuentas.length), h: "procesadas" },
      { k: "Tiempo", v: `${ms.toFixed(1)} ms`, h: "lote completo" },
      { k: "Throughput", v: `${((cuentas.length / ms) * 1000).toFixed(0)}/s`, h: "CVE locales" },
      { k: "CED", v: keys.cedCompleta.slice(0, 8) + "…", h: "Triple DES" },
    ]);
    show(out, `<span class="warn">Lote OK · descarga informe TXT</span>\n` + html);
  });

  document.getElementById("lab-bench").addEventListener("click", () => {
    const out = document.getElementById("out-lab");
    const keys = keysFromForm();
    const bench = motor.benchmarkCVE({
      claveA: keys.claveA,
      claveB: keys.claveB,
      codigoPerfil: document.getElementById("cve-perfil").value,
      iteraciones: 400,
    });
    paintMetrics([
      { k: "Iteraciones", v: String(bench.iteraciones) },
      { k: "Tiempo", v: `${bench.ms} ms` },
      { k: "Velocidad", v: `${bench.opsPorSeg} CVE/s`, h: "este navegador" },
      { k: "Motor", v: "JS local", h: "no HSM" },
    ]);
    const txt =
      `# Benchmark CVE\n` +
      `# ${new Date().toISOString()}\n` +
      `iteraciones=${bench.iteraciones}\n` +
      `ms=${bench.ms}\n` +
      `ops_por_seg=${bench.opsPorSeg}\n` +
      `nota=${bench.nota}\n`;
    ultimoInforme = txt;
    document.getElementById("lab-download").disabled = false;
    show(out, `<span class="warn">Benchmark</span>\n${bench.nota}\n${bench.opsPorSeg} operaciones/s`);
  });

  document.getElementById("lab-guess").addEventListener("click", () => {
    const out = document.getElementById("out-lab");
    const keys = keysFromForm();
    const cuentas = motor.parsePegado(document.getElementById("lab-paste").value);
    const sample = cuentas[0] || {
      ncd: document.getElementById("cve-ncd").value,
      fechaDemo: document.getElementById("cve-fecha").value,
    };
    const sim = motor.simularAdivinanzaCVE({
      ncd: sample.ncd,
      fechaDemo: sample.fechaDemo,
      codigoPerfil: document.getElementById("cve-perfil").value,
      claveA: keys.claveA,
      claveB: keys.claveB,
    });
    paintMetrics([
      { k: "CVE objetivo", v: sim.cveObjetivo, h: "sandbox" },
      { k: "Intentos", v: String(sim.intentosHastaAcierto), h: `de ${sim.espacio}` },
      { k: "Tiempo local", v: `${sim.ms} ms`, h: "sin rate-limit" },
      { k: "Riesgo", v: "ALTO", h: "salida 3 dígitos" },
    ]);
    ultimoInforme =
      `# Simulación educativa adivinanza CVE (solo sandbox local)\n` +
      `# ${new Date().toISOString()}\n` +
      `ncd=${sample.ncd}\n` +
      `fecha=${sample.fechaDemo}\n` +
      `cve=${sim.cveObjetivo}\n` +
      `intentos=${sim.intentosHastaAcierto}\n` +
      `ms=${sim.ms}\n` +
      `conclusion=${sim.conclusion}\n`;
    document.getElementById("lab-download").disabled = false;
    show(out, `<span class="warn">Simulación educativa (no ataca sistemas reales)</span>\n${sim.conclusion}`);
  });

  document.getElementById("lab-report").addEventListener("click", () => {
    const out = document.getElementById("out-lab");
    const keys = keysFromForm();
    const a = motor.analizarFuerzaCVE();
    const b = motor.analizarFuerzaCDT(30);
    const bench = motor.benchmarkCVE({
      claveA: keys.claveA,
      claveB: keys.claveB,
      codigoPerfil: document.getElementById("cve-perfil").value,
      iteraciones: 300,
    });

    paintMetrics([
      { k: "CVE espacio", v: String(a.espacioSalida), h: `~${a.bitsSalidaAprox} bits` },
      { k: "CDT espacio", v: String(b.espacioSalida), h: `~${b.bitsSalidaAprox} bits` },
      { k: "Clave 3DES", v: `~${a.bitsClaveAprox} bits`, h: "si CED protegida" },
      { k: "Velocidad", v: `${bench.opsPorSeg}/s`, h: "motor JS" },
    ]);

    const mejoras = [...a.mejoras, ...b.mejoras].map((m, i) => `${i + 1}. ${m}`).join("\n");
    ultimoInforme =
      `# Informe ciberseguridad EduCard Lab\n` +
      `# ${new Date().toISOString()}\n` +
      `# CED usada (demo): ${keys.cedCompleta}\n\n` +
      `## Método A — CVE\n` +
      `algoritmo=${a.algoritmo}\n` +
      `espacio_salida=${a.espacioSalida}\n` +
      `bits_salida_aprox=${a.bitsSalidaAprox}\n` +
      `bits_clave_aprox=${a.bitsClaveAprox}\n` +
      `veredicto=${a.veredictoSalida}\n\n` +
      `## Método B — CDT\n` +
      `algoritmo=${b.algoritmo}\n` +
      `espacio_salida=${b.espacioSalida}\n` +
      `bits_salida_aprox=${b.bitsSalidaAprox}\n` +
      `ventana_s=${b.ventanaSegundos}\n` +
      `veredicto=${b.veredictoSalida}\n\n` +
      `## Benchmark local\n` +
      `ops_por_seg=${bench.opsPorSeg}\n` +
      `ms=${bench.ms}\n\n` +
      `## Mejoras recomendadas\n` +
      `${mejoras}\n`;

    document.getElementById("lab-download").disabled = false;
    show(
      out,
      `<span class="warn">Informe CVE vs CDT</span>\n\n` +
        `<strong>CVE:</strong> ${a.veredictoSalida}\n\n` +
        `<strong>CDT:</strong> ${b.veredictoSalida}\n\n` +
        `Mejoras:\n${mejoras.replace(/\n/g, "<br>")}`
    );
  });

  document.getElementById("lab-download").addEventListener("click", () => {
    if (!ultimoInforme) return;
    descargar(ultimoInforme, "informe_cyber_educard.txt");
  });
})();
