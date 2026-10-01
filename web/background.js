"use strict";

(() => {
  const storageKey = "aegisgate.consoleBackground.v1";
  const themeStorageKey = "aegisgate.glassTheme.v1";
  const presets = {
    architecture: { name: "几何光影", source: "/assets/glass-architecture.svg", accent: [140, 215, 198] },
    landscape: { name: "抽象山湖", source: "/assets/glass-landscape.svg", accent: [156, 201, 237] },
  };
  const defaultBackground = { type: "preset", id: "architecture" };
  const dialog = byId("backgroundDialog");
  let selection = defaultBackground;
  let busy = false;
  let accentRevision = 0;

  function setAccent(rgb) {
    const channels = rgb.join(", ");
    document.documentElement.style.setProperty("--accent-rgb", channels);
    document.dispatchEvent(new CustomEvent("aegis:accent-changed", {
      detail: { color: `rgb(${channels})`, fill: `rgba(${channels}, .12)` },
    }));
  }

  function sampleAccent(image) {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 24;
    const context = canvas.getContext("2d");
    if (!context) return presets.architecture.accent;
    context.drawImage(image, 0, 0, 24, 24);
    const pixels = context.getImageData(0, 0, 24, 24).data;
    const buckets = new Array(12).fill(0);
    // Ignore neutral pixels; hue buckets prevent opposing colors averaging gray.
    for (let i = 0; i < pixels.length; i += 4) {
      const [r, g, b, alpha] = pixels.subarray(i, i + 4);
      const maximum = Math.max(r, g, b), minimum = Math.min(r, g, b), delta = maximum - minimum;
      if (alpha < 220 || delta < 16 || maximum < 45 || minimum > 225) continue;
      let hue = maximum === r ? (g - b) / delta : maximum === g ? 2 + (b - r) / delta : 4 + (r - g) / delta;
      hue = (hue * 60 + 360) % 360;
      buckets[Math.floor(hue / 30)] += delta / 255;
    }
    const strongest = Math.max(...buckets);
    if (strongest < 3) return presets.architecture.accent;
    const hue = buckets.indexOf(strongest) * 30 + 15;
    const lightness = .74, amplitude = .55 * (1 - lightness);
    const channel = offset => {
      const k = (offset + hue / 30) % 12;
      return Math.round(255 * (lightness - amplitude * Math.max(-1, Math.min(k - 3, 9 - k, 1))));
    };
    return [channel(0), channel(8), channel(4)];
  }

  function adaptAccent(value, source) {
    const revision = ++accentRevision;
    if (value.type === "preset") {
      setAccent(presets[value.id].accent);
      return;
    }
    setAccent(presets.architecture.accent);
    const image = new Image();
    image.onload = () => {
      if (revision !== accentRevision) return;
      try { setAccent(sampleAccent(image)); } catch (_) { /* Keep the readable default accent if sampling fails. */ }
    };
    image.src = source;
  }

  function validBackground(value) {
    if (!value || typeof value !== "object") return false;
    if (value.type === "preset") return Object.hasOwn(presets, value.id);
    return value.type === "upload" && typeof value.name === "string" && typeof value.source === "string"
      && value.source.length <= 3 * 1024 * 1024 && /^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(value.source);
  }

  function showBackgroundError(message = "") {
    byId("backgroundError").textContent = message;
    byId("backgroundError").hidden = !message;
  }

  function applyBackground(value) {
    const { source, name } = value.type === "preset" ? presets[value.id] : value;
    document.documentElement.style.setProperty("--workspace-background", `url("${source}")`);
    document.dispatchEvent(new CustomEvent("aegis:background-changed", { detail: { source, name, value } }));
    byId("backgroundPreview").src = source;
    byId("backgroundName").textContent = name;
    document.querySelectorAll("[data-background-preset]").forEach(button => {
      button.setAttribute("aria-pressed", String(value.type === "preset" && value.id === button.dataset.backgroundPreset));
    });
    selection = value;
    adaptAccent(value, source);
  }

  function saveBackground(value, reset = false) {
    try {
      if (reset) localStorage.removeItem(storageKey);
      else localStorage.setItem(storageKey, JSON.stringify(value));
    } catch (_) {
      showBackgroundError("背景未保存，浏览器存储空间不足或存储不可用。");
      return;
    }
    applyBackground(value);
    showBackgroundError();
    showToast(reset ? "已恢复默认背景" : "背景已更新");
  }

  function setBusy(value) {
    busy = value;
    dialog.setAttribute("aria-busy", String(value));
    byId("backgroundUploadLabel").textContent = value ? "正在处理图片…" : "选择本地图片";
    byId("uploadBackgroundButton").disabled = value;
    byId("resetBackgroundButton").disabled = value;
    document.querySelectorAll("[data-background-preset]").forEach(button => { button.disabled = value; });
  }

  function readImage(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error("图片读取失败，请重新选择。"));
      reader.onload = () => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error("无法识别这张图片，请选择有效的 JPG、PNG 或 WebP 图片。"));
        image.src = reader.result;
      };
      reader.readAsDataURL(file);
    });
  }

  async function uploadBackground(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || busy) return;
    showBackgroundError();
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.type)) {
      showBackgroundError("请选择 JPG、PNG 或 WebP 图片。");
      return;
    }
    if (file.size > 20 * 1024 * 1024) {
      showBackgroundError("图片超过 20 MB，请选择较小的图片。");
      return;
    }
    setBusy(true);
    try {
      const image = await readImage(file);
      const canvas = document.createElement("canvas");
      const scale = Math.min(1, 2560 / Math.max(image.naturalWidth, image.naturalHeight));
      canvas.width = Math.max(1, Math.round(image.naturalWidth * scale));
      canvas.height = Math.max(1, Math.round(image.naturalHeight * scale));
      const context = canvas.getContext("2d");
      if (!context) throw new Error("当前浏览器无法处理图片。");
      context.fillStyle = "#252525";
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.drawImage(image, 0, 0, canvas.width, canvas.height);
      let source = canvas.toDataURL("image/jpeg", .86);
      if (source.length > 3 * 1024 * 1024) source = canvas.toDataURL("image/jpeg", .65);
      if (source.length > 3 * 1024 * 1024) throw new Error("图片压缩后仍然过大，请选择较小的图片。");
      saveBackground({ type: "upload", name: file.name, source });
    } catch (error) {
      showBackgroundError(error.message || "图片处理失败，请重新选择。");
    } finally {
      setBusy(false);
    }
  }

  byId("backgroundSettingsButton").addEventListener("click", () => {
    showBackgroundError();
    if (!dialog.open) dialog.showModal();
  });
  byId("closeBackgroundButton").addEventListener("click", () => dialog.close());
  byId("uploadBackgroundButton").addEventListener("click", () => byId("backgroundFileInput").click());
  byId("backgroundFileInput").addEventListener("change", uploadBackground);
  byId("resetBackgroundButton").addEventListener("click", () => saveBackground(defaultBackground, true));
  document.querySelectorAll("[data-background-preset]").forEach(button => {
    button.addEventListener("click", () => saveBackground({ type: "preset", id: button.dataset.backgroundPreset }));
  });
  try {
    const stored = JSON.parse(localStorage.getItem(storageKey));
    if (validBackground(stored)) selection = stored;
  } catch (_) {
    // A disabled or invalid preference must not prevent the console loading.
  }
  function applyGlassTheme(theme) {
    document.documentElement.dataset.glassTheme = theme === "light" ? "light" : "dark";
    document.querySelectorAll("[data-glass-theme]").forEach(button => {
      if (button.tagName === "BUTTON") button.setAttribute("aria-pressed", String(button.dataset.glassTheme === theme));
    });
  }
  let theme = "dark";
  try { if (localStorage.getItem(themeStorageKey) === "light") theme = "light"; } catch (_) { /* Use the default when storage is unavailable. */ }
  applyGlassTheme(theme);
  document.querySelectorAll("button[data-glass-theme]").forEach(button => {
    button.addEventListener("click", () => {
      applyGlassTheme(button.dataset.glassTheme);
      try { localStorage.setItem(themeStorageKey, button.dataset.glassTheme); } catch (_) { /* The current session still applies. */ }
    });
  });
  applyBackground(selection);
})();
