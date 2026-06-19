/**
 * WebShield Chrome Extension — Popup Script
 *
 * Runs when the user clicks the extension icon in the toolbar.
 * Reads the active tab's URL, retrieves cached scan results from
 * chrome.storage.local, and renders the status in the popup UI.
 * Also handles the "Scan Again" button for force-refreshing.
 */

(function () {
  "use strict";

  // Risk score threshold: >= this value is treated as unsafe
  const UNSAFE_THRESHOLD = 40;

  // Chrome security interstitial keywords in tab titles (multilingual support)
  const CHROME_WARNING_KEYWORDS = [
    // English
    "deceptive site", "dangerous site", "privacy error", "connection is not private",
    "site ahead contains", "phishing warning", "malware warning", "suspicious site",
    "security warning", "security error",
    // Hindi
    "भ्रामक", "खतरनाक साइट", "गोपनीयता", "सुरक्षा चेतावनी",
    // Spanish
    "sitio engañoso", "sitio peligroso", "error de privacidad", "conexión no es privada",
    "advertencia de seguridad",
    // French
    "site trompeur", "site dangerous", "erreur de confidentialité", "connexion n'est pas sécurisée",
    "avertissement de sécurité",
    // German
    "irreführende", "gefährliche website", "datenschutzfehler", "sicherheitswarnung",
    // Portuguese
    "site enganoso", "site perigoso", "erro de privacidade", "conexão não é privada",
    // Russian
    "опасный сайт", "ошибка конфиденциальности", "подключение не защищено",
    // Chinese
    "欺骗性", "危险网站", "隐私权专有错误", "连接不是私密", "安全警告",
    // Japanese
    "偽のサイト", "危険なサイト", "プライバシーのエラー", "接続はプライベート", "セキュリティ警告"
  ];

  function isChromeWarningTitle(title) {
    if (!title) return false;
    const lowerTitle = title.toLowerCase();
    return CHROME_WARNING_KEYWORDS.some(keyword => lowerTitle.includes(keyword));
  }

  // DOM references
  const statusBadge = document.getElementById("status-badge");
  const statusRing = document.getElementById("status-ring");
  const statusIconInner = document.getElementById("status-icon-inner");
  const iconLoading = document.getElementById("icon-loading");
  const iconSafe = document.getElementById("icon-safe");
  const iconDanger = document.getElementById("icon-danger");
  const iconError = document.getElementById("icon-error");
  const statusTitle = document.getElementById("status-title");
  const statusMessage = document.getElementById("status-message");
  const currentUrlEl = document.getElementById("current-url");
  const detailsSection = document.getElementById("details-section");
  const signalsList = document.getElementById("signals-list");
  const btnScan = document.getElementById("btn-scan");
  const datasetStatus = document.getElementById("dataset-status");

  let currentTabUrl = "";

  /**
   * Initialize: get the active tab and display its scan status.
   */
  async function init() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        currentTabUrl = tab.url;
        currentUrlEl.textContent = truncateUrl(tab.url, 50);
        currentUrlEl.title = tab.url;

        // Check if Chrome itself flagged this page via tab title
        if (tab.title && isChromeWarningTitle(tab.title)) {
          const chromeUnsafeResult = {
            url: tab.url,
            status: "unsafe",
            safe: false,
            risk_score: 99,
            risk_level: "dangerous",
            detection_method: "chrome_safe_browsing",
            signals: ["Google Chrome Safe Browsing flagged this website as dangerous/suspicious."],
            message: "Google Chrome flagged this website as unsafe."
          };
          renderResult(chromeUnsafeResult);
          return;
        }

        // Check if it's an internal page
        if (isInternalPage(tab.url)) {
          showInternalPage();
          return;
        }

        // Try to get cached result
        const cacheKey = `cache_${tab.url}`;
        const data = await chrome.storage.local.get([cacheKey, "latestResult"]);

        if (data[cacheKey] && data[cacheKey].result) {
          renderResult(data[cacheKey].result);
        } else if (data.latestResult && data.latestResult.url === tab.url) {
          renderResult(data.latestResult);
        } else {
          // No cached result — trigger a fresh scan
          triggerScan(tab.url);
        }
      } else {
        showInternalPage();
      }
    } catch (e) {
      showError("Could not access tab information.");
    }
  }

  /**
   * Render a scan result in the popup UI.
   */
  function renderResult(result) {
    // Hide loading, show appropriate icon
    iconLoading.classList.add("hidden");
    iconSafe.classList.add("hidden");
    iconDanger.classList.add("hidden");
    iconError.classList.add("hidden");

    detailsSection.classList.remove("hidden");

    const isUnsafe = result.risk_score >= UNSAFE_THRESHOLD;

    if (!isUnsafe) {
      // ── Safe State ──
      iconSafe.classList.remove("hidden");
      statusRing.className = "status-ring safe";
      statusIconInner.className = "status-icon-inner safe";
      statusBadge.className = "header-badge safe";
      statusBadge.textContent = "Safe";
      statusTitle.className = "status-title safe";
      statusTitle.textContent = "Website is Safe";
      statusMessage.textContent = result.message || "No threats detected.";
    } else {
      // ── Unsafe State ──
      iconDanger.classList.remove("hidden");
      statusRing.className = "status-ring danger";
      statusIconInner.className = "status-icon-inner danger";
      statusBadge.className = "header-badge danger";
      statusBadge.textContent = "Unsafe";
      statusTitle.className = "status-title danger";
      statusTitle.textContent = "Unsafe Website Detected!";
      statusMessage.textContent = result.message || "This site has been flagged as dangerous.";
    }

    // Signals
    signalsList.innerHTML = "";
    const signals = result.signals || [];
    if (signals.length > 0) {
      signals.forEach(sig => {
        const li = document.createElement("li");
        li.textContent = sig;
        if (isUnsafe) li.classList.add("danger");
        signalsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "No risk signals flagged.";
      signalsList.appendChild(li);
    }

    // Backend status
    datasetStatus.textContent = "Backend Connected";
    datasetStatus.style.color = "#4b5563";
  }

  /**
   * Trigger a fresh scan via the background service worker.
   */
  function triggerScan(url) {
    showLoading();
    btnScan.classList.add("scanning");
    btnScan.textContent = "Scanning...";

    chrome.runtime.sendMessage(
      { action: "force_scan", url },
      (response) => {
        btnScan.classList.remove("scanning");
        btnScan.innerHTML = `
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5">
            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
          Scan Again
        `;

        if (response && response.result) {
          renderResult(response.result);
        } else {
          showError("Backend unreachable. Is the server running?");
        }
      }
    );
  }

  /**
   * Show loading state in the popup.
   */
  function showLoading() {
    iconLoading.classList.remove("hidden");
    iconSafe.classList.add("hidden");
    iconDanger.classList.add("hidden");
    iconError.classList.add("hidden");
    statusRing.className = "status-ring";
    statusIconInner.className = "status-icon-inner";
    statusBadge.className = "header-badge";
    statusBadge.textContent = "Scanning...";
    statusTitle.className = "status-title";
    statusTitle.textContent = "Analyzing...";
    statusMessage.textContent = "Checking website against threat database";
    detailsSection.classList.add("hidden");
  }

  /**
   * Show error state when backend is unreachable.
   */
  function showError(msg) {
    iconLoading.classList.add("hidden");
    iconSafe.classList.add("hidden");
    iconDanger.classList.add("hidden");
    iconError.classList.remove("hidden");
    statusRing.className = "status-ring offline";
    statusIconInner.className = "status-icon-inner offline";
    statusBadge.className = "header-badge offline";
    statusBadge.textContent = "Offline";
    statusTitle.className = "status-title";
    statusTitle.textContent = "Connection Error";
    statusMessage.textContent = msg;
    detailsSection.classList.add("hidden");
    datasetStatus.textContent = "Backend Offline";
    datasetStatus.style.color = "#ef4444";
  }

  /**
   * Show state for internal browser pages.
   */
  function showInternalPage() {
    iconLoading.classList.add("hidden");
    iconSafe.classList.remove("hidden");
    iconDanger.classList.add("hidden");
    iconError.classList.add("hidden");
    statusRing.className = "status-ring safe";
    statusIconInner.className = "status-icon-inner safe";
    statusBadge.className = "header-badge safe";
    statusBadge.textContent = "N/A";
    statusTitle.className = "status-title safe";
    statusTitle.textContent = "Internal Page";
    statusMessage.textContent = "Browser pages are not scanned.";
    detailsSection.classList.add("hidden");
  }

  // ── Helpers ──────────────────────────────

  function isInternalPage(url) {
    const skip = ["chrome://", "chrome-extension://", "about:", "edge://",
      "brave://", "devtools://", "view-source:", "data:", "blob:", "file://", "chrome-error://"];
    return skip.some(p => url.startsWith(p));
  }

  function truncateUrl(url, max) {
    if (url.length <= max) return url;
    return url.substring(0, max) + "…";
  }

  function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  function formatMethod(method) {
    const map = {
      exact: "Database Check",
      trusted: "Trusted Site",
      whitelist_bypass: "Trusted Site"
    };
    return map[method] || method || "—";
  }

  // ── Event Listeners ─────────────────────

  btnScan.addEventListener("click", () => {
    if (currentTabUrl && !isInternalPage(currentTabUrl)) {
      triggerScan(currentTabUrl);
    }
  });

  // Initialize on load
  init();
})();
