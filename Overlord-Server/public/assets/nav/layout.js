import { NAV_MODE_KEY } from "./template.js";

const LS_KEY = "sb_collapsed";
const MOBILE_BP = 768;

function createTopbarController(host, refs) {
  const { toggle, panel, navLinks, navUtility } = refs;
  if (!toggle || !panel || !navLinks || !navUtility) {
    return { applyAdaptiveNavLayout: () => {} };
  }

  const navOverflows = () =>
    panel.scrollWidth > panel.clientWidth + 1 || host.scrollWidth > host.clientWidth + 1;

  function resetInlineStyles() {
    panel.style.display = "";
    panel.style.flexDirection = "";
    panel.style.alignItems = "";
    panel.style.gap = "";
    navLinks.style.flexDirection = "";
    navLinks.style.flexWrap = "";
    navLinks.style.alignItems = "";
    navLinks.style.justifyContent = "";
    navUtility.style.display = "";
    navUtility.style.width = "";
    navUtility.style.justifyContent = "";
    navUtility.style.flexWrap = "";
  }

  function applyAdaptiveNavLayout() {
    if (window.innerWidth < MOBILE_BP) {
      host.dataset.navMode = "mobile";
      panel.classList.add("hidden");
      resetInlineStyles();
      panel.dataset.open = "false";
      toggle.style.display = "";
      toggle.setAttribute("aria-expanded", "false");
      return;
    }

    host.dataset.navMode = "desktop";
    panel.classList.remove("hidden");
    panel.style.display = "flex";
    panel.dataset.open = "true";
    navUtility.style.display = "flex";
    toggle.style.display = "none";
    toggle.setAttribute("aria-expanded", "false");

    if (navOverflows()) {
      host.dataset.navMode = "desktop-compact";
      navUtility.style.display = "none";
      if (navOverflows()) {
        host.dataset.navMode = "compact";
        panel.style.display = "none";
        panel.dataset.open = "false";
        toggle.style.display = "inline-flex";
      }
    }
  }

  function openCompactPanel() {
    panel.dataset.open = "true";
    panel.classList.remove("hidden");
    panel.style.display = "flex";
    panel.style.flexDirection = "column";
    panel.style.alignItems = "stretch";
    panel.style.gap = "10px";
    navLinks.style.flexDirection = "row";
    navLinks.style.flexWrap = "wrap";
    navLinks.style.alignItems = "center";
    navLinks.style.justifyContent = "flex-start";
    navUtility.style.display = "flex";
    navUtility.style.width = "100%";
    navUtility.style.justifyContent = "space-between";
    navUtility.style.flexWrap = "wrap";
    toggle.setAttribute("aria-expanded", "true");
  }

  function closeCompactPanel() {
    panel.dataset.open = "false";
    panel.style.display = "none";
    if (host.dataset.navMode === "mobile") panel.classList.add("hidden");
    toggle.setAttribute("aria-expanded", "false");
  }

  toggle.addEventListener("click", () => {
    const compact =
      host.dataset.navMode === "compact" || host.dataset.navMode === "mobile";
    if (!compact) return;
    if (panel.dataset.open === "true") {
      closeCompactPanel();
    } else {
      openCompactPanel();
    }
  });

  let resizeRaf = null;
  window.addEventListener("resize", () => {
    if (resizeRaf) cancelAnimationFrame(resizeRaf);
    resizeRaf = requestAnimationFrame(applyAdaptiveNavLayout);
  });

  applyAdaptiveNavLayout();
  return { applyAdaptiveNavLayout };
}

function createSidebarController(host, refs) {
  const { collapseBtn, toggle } = refs;
  const backdrop = document.getElementById("sb-backdrop");
  const navLinks = document.getElementById("nav-links");

  document.body.classList.add("sb-ready");

  let collapsed = localStorage.getItem(LS_KEY) === "true";
  if (collapsed) document.body.classList.add("sb-collapsed");

  function setCollapsed(val) {
    collapsed = val;
    localStorage.setItem(LS_KEY, String(val));
    document.body.classList.toggle("sb-collapsed", val);
  }

  function isMobile() { return window.innerWidth < MOBILE_BP; }
  function openMobile() { document.body.classList.add("sb-open"); }
  function closeMobile() { document.body.classList.remove("sb-open"); }

  if (collapseBtn) {
    collapseBtn.addEventListener("click", () => {
      if (!isMobile()) setCollapsed(!collapsed);
    });
  }
  if (toggle) toggle.addEventListener("click", openMobile);
  if (backdrop) backdrop.addEventListener("click", closeMobile);
  window.addEventListener("resize", () => { if (!isMobile()) closeMobile(); });

  return { applyAdaptiveNavLayout: () => {} };
}

export function createAdaptiveNavController(host, refs) {
  const mode = localStorage.getItem(NAV_MODE_KEY);
  if (mode === "sidebar") {
    return createSidebarController(host, refs);
  }
  return createTopbarController(host, refs);
}

