"use strict";

(() => {
  const root = document.documentElement;
  const canvas = document.getElementById("glassShaderCanvas");
  if (!canvas) return;

  const surfaceSelector = [
    ".app-sidebar", ".topbar", ".home-kpi", ".dashboard-widget", ".metric-strip",
    ".official-band", ".testing-pane", ".result-pane", ".runtime-summary", ".system-card",
    ".batch-kpis > div", ".audit-kpis > div", ".ops-kpi", ".ops-sidebar", ".tool-panel",
    ".enterprise-kpis", ".enterprise-module-nav", ".enterprise-table-wrap",
    ".home-quick-access", "dialog", ".nav-search-results", ".toast",
  ].join(",");
  let gl = null;
  let sourceTexture = null;
  let transparentTexture = null;
  let quad = null;
  let programs = null;
  let targets = [];
  let sourceImage = null;
  let sourceRevision = 0;
  let frame = 0;
  let targetWidth = 0;
  let targetHeight = 0;
  let textureDirty = true;
  let viewWidth = 1;
  let viewHeight = 1;
  let sourceUrl = document.getElementById("backgroundPreview")?.src || "/assets/glass-architecture.svg";

  function fallback(reason) {
    if (reason) console.warn("Glass backdrop fallback:", reason);
    root.classList.remove("glass-shader-ready");
    root.dataset.glassRenderer = "css";
  }

  function compile(type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      const message = gl.getShaderInfoLog(shader) || "GLSL compile failed";
      gl.deleteShader(shader);
      throw new Error(message);
    }
    return shader;
  }

  function createProgram(vertexSource, fragmentSource) {
    const handle = gl.createProgram();
    const vertex = compile(gl.VERTEX_SHADER, vertexSource);
    const fragment = compile(gl.FRAGMENT_SHADER, fragmentSource);
    gl.attachShader(handle, vertex);
    gl.attachShader(handle, fragment);
    gl.linkProgram(handle);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (!gl.getProgramParameter(handle, gl.LINK_STATUS)) {
      const message = gl.getProgramInfoLog(handle) || "GLSL link failed";
      gl.deleteProgram(handle);
      throw new Error(message);
    }
    return { handle, position: gl.getAttribLocation(handle, "a_position"), uniforms: new Map() };
  }

  function getUniform(program, name) {
    if (!program.uniforms.has(name)) program.uniforms.set(name, gl.getUniformLocation(program.handle, name));
    return program.uniforms.get(name);
  }

  function createTexture(width = 1, height = 1, pixels = null) {
    const handle = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, handle);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    if (pixels) gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    else gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    return handle;
  }

  function releaseTargets() {
    for (const target of targets) {
      gl.deleteFramebuffer(target.framebuffer);
      gl.deleteTexture(target.texture);
    }
    targets = [];
  }

  function resize() {
    viewWidth = Math.max(1, root.clientWidth);
    viewHeight = Math.max(1, window.innerHeight || document.documentElement.clientHeight || 1);
    const scale = Math.min(1 / 3, 1440 / Math.max(viewWidth, viewHeight));
    const nextWidth = Math.max(1, Math.round(viewWidth * scale));
    const nextHeight = Math.max(1, Math.round(viewHeight * scale));
    if (nextWidth === targetWidth && nextHeight === targetHeight) return;
    targetWidth = nextWidth;
    targetHeight = nextHeight;
    canvas.width = targetWidth;
    canvas.height = targetHeight;
    releaseTargets();
    for (let index = 0; index < 2; index += 1) {
      const target = { texture: createTexture(targetWidth, targetHeight), framebuffer: gl.createFramebuffer() };
      targets.push(target);
      gl.bindFramebuffer(gl.FRAMEBUFFER, target.framebuffer);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, target.texture, 0);
      if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) throw new Error("Backdrop framebuffer incomplete");
    }
  }

  function bindPass(program, target, inputTexture) {
    gl.bindFramebuffer(gl.FRAMEBUFFER, target ? target.framebuffer : null);
    gl.viewport(0, 0, targetWidth, targetHeight);
    gl.useProgram(program.handle);
    gl.bindBuffer(gl.ARRAY_BUFFER, quad);
    gl.enableVertexAttribArray(program.position);
    gl.vertexAttribPointer(program.position, 2, gl.FLOAT, false, 0, 0);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, inputTexture);
    gl.uniform1i(getUniform(program, "u_background"), 0);
  }

  function draw() {
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  }

  function syncSurfaces() {
    document.querySelectorAll(surfaceSelector).forEach(surface => {
      // Floating menus need their own backdrop; in-card groups share the parent.
      const floating = surface.matches("dialog, .nav-search-results, .toast");
      const nested = surface.parentElement && surface.parentElement.closest(surfaceSelector);
      surface.classList.toggle("glass-surface", floating || !nested);
    });
  }

  function render() {
    frame = 0;
    if (!gl || !programs || !sourceImage || gl.isContextLost()) return;
    try {
      resize();
      gl.activeTexture(gl.TEXTURE0);
      if (textureDirty) {
        gl.bindTexture(gl.TEXTURE_2D, sourceTexture);
        gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, sourceImage);
        textureDirty = false;
      }
      bindPass(programs.capture, targets[0], sourceTexture);
      gl.uniform2f(getUniform(programs.capture, "u_imageSize"), sourceImage.naturalWidth || sourceImage.width, sourceImage.naturalHeight || sourceImage.height);
      gl.uniform2f(getUniform(programs.capture, "u_viewport"), viewWidth, viewHeight);
      draw();

      bindPass(programs.blur, targets[1], targets[0].texture);
      gl.uniform2f(getUniform(programs.blur, "u_texelStep"), 1 / targetWidth, 0);
      gl.uniform1f(getUniform(programs.blur, "u_sigma"), 30 * targetWidth / viewWidth);
      draw();
      bindPass(programs.blur, targets[0], targets[1].texture);
      gl.uniform2f(getUniform(programs.blur, "u_texelStep"), 0, 1 / targetHeight);
      gl.uniform1f(getUniform(programs.blur, "u_sigma"), 30 * targetHeight / viewHeight);
      draw();

      bindPass(programs.material, null, targets[0].texture);
      gl.activeTexture(gl.TEXTURE1);
      gl.bindTexture(gl.TEXTURE_2D, transparentTexture);
      gl.uniform1i(getUniform(programs.material, "u_foreground"), 1);
      gl.uniform1f(getUniform(programs.material, "u_hasForeground"), 0);
      gl.uniform1f(getUniform(programs.material, "u_vibrancy"), 0);
      gl.uniform1f(getUniform(programs.material, "u_saturation"), 0.72);
      gl.uniform1f(getUniform(programs.material, "u_compression"), 0.6);
      const lightMode = root.dataset.glassTheme === "light";
      gl.uniform1f(getUniform(programs.material, "u_lightMode"), lightMode ? 1 : 0);
      gl.uniform1f(getUniform(programs.material, "u_tintOpacity"), lightMode ? 0.04 : 0.025);
      draw();
      if (gl.getError() !== gl.NO_ERROR) throw new Error("Backdrop rendering failed");
      // Publish only background pixels. DOM text and icons are painted afterwards.
      root.style.setProperty("--glass-backdrop", `url("${canvas.toDataURL("image/png")}")`);
      root.style.setProperty("--glass-viewport", `${viewWidth}px ${viewHeight}px`);
      root.classList.add("glass-shader-ready");
      root.dataset.glassRenderer = "webgl";
      syncSurfaces();
    } catch (error) {
      fallback(error.message);
    }
  }

  function schedule() {
    if (!frame) frame = requestAnimationFrame(render);
  }

  function loadSource(source) {
    if (!source) return;
    sourceUrl = source;
    const current = ++sourceRevision;
    sourceImage = null;
    fallback();
    const image = new Image();
    image.onload = () => {
      if (current !== sourceRevision) return;
      sourceImage = image;
      textureDirty = true;
      schedule();
    };
    image.onerror = () => { if (current === sourceRevision) fallback("Background image unavailable"); };
    image.src = source;
  }

  async function loadShader(name) {
    const response = await fetch("/shaders/" + name, { credentials: "same-origin" });
    if (!response.ok) throw new Error("Cannot load shader: " + name);
    return response.text();
  }

  async function initialize() {
    try {
      const shaderSources = await Promise.all(["fullscreen.vert", "backdrop.frag", "gaussian.frag", "material.frag"].map(loadShader));
      gl = canvas.getContext("webgl", { alpha: false, antialias: false, depth: false, stencil: false });
      if (!gl) throw new Error("WebGL unavailable");
      // All handles from a lost context are invalid, even at the same viewport size.
      targets = [];
      targetWidth = targetHeight = 0;
      programs = {
        capture: createProgram(shaderSources[0], shaderSources[1]),
        blur: createProgram(shaderSources[0], shaderSources[2]),
        material: createProgram(shaderSources[0], shaderSources[3]),
      };
      quad = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, quad);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
      sourceTexture = createTexture();
      transparentTexture = createTexture(1, 1, new Uint8Array([0, 0, 0, 0]));
      loadSource(sourceUrl);
    } catch (error) {
      fallback(error.message);
    }
  }

  canvas.addEventListener("webglcontextlost", event => {
    event.preventDefault();
    fallback("WebGL context lost");
  });
  canvas.addEventListener("webglcontextrestored", () => initialize());
  document.addEventListener("aegis:background-changed", event => loadSource(event.detail && event.detail.source));
  window.addEventListener("resize", schedule, { passive: true });
  new MutationObserver(schedule).observe(root, { attributes: true, attributeFilter: ["data-glass-theme"] });
  new MutationObserver(syncSurfaces).observe(document.body, { childList: true, subtree: true });
  syncSurfaces();
  initialize();
})();
