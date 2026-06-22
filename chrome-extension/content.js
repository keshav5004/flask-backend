/**
 * WebShield Chrome Extension — Content Script
 *
 * Injected into every webpage. Listens for messages from the
 * background service worker and injects/removes a full-screen
 * phishing warning overlay when a malicious site is detected.
 */

(function () {
  "use strict";

  const OVERLAY_ID = "webshield-phishing-overlay";
  const STYLE_ID = "webshield-overlay-styles";
  const UNSAFE_THRESHOLD = 40;

  /**
   * Remove any existing overlay from the page.
   */
  function removeOverlay() {
    const existing = document.getElementById(OVERLAY_ID);
    if (existing) {
      existing.style.opacity = "0";
      setTimeout(() => existing.remove(), 300);
    }
    const style = document.getElementById(STYLE_ID);
    if (style) style.remove();
  }

  /**
   * Inject the full-screen phishing warning overlay.
   */
  function injectOverlay(result) {
    // Don't double-inject
    if (document.getElementById(OVERLAY_ID)) return;

    // Build signals HTML
    const signalsHtml = (result.signals || [])
      .map(s => `<li>${escapeHtml(s)}</li>`)
      .join("");

    // Inject scoped styles
    const styleEl = document.createElement("style");
    styleEl.id = STYLE_ID;
    styleEl.textContent = `
      #${OVERLAY_ID} {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 2147483647 !important;
        background: rgba(5, 5, 15, 0.97) !important;
        display: flex !important;
        align-items: flex-start !important;
        justify-content: center !important;
        overflow-y: auto !important;
        padding: 24px 16px !important;
        font-family: 'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        opacity: 0;
        transition: opacity 0.3s ease !important;
        backdrop-filter: blur(8px) !important;
      }
      #${OVERLAY_ID}.ws-visible {
        opacity: 1 !important;
      }
      #${OVERLAY_ID} * {
        box-sizing: border-box !important;
      }
      .ws-warning-card {
        background: linear-gradient(145deg, rgba(25, 10, 15, 0.95), rgba(40, 10, 20, 0.9)) !important;
        border: 2px solid rgba(255, 0, 85, 0.6) !important;
        border-radius: 20px !important;
        padding: 32px 28px !important;
        max-width: 480px !important;
        width: 92% !important;
        margin: auto !important;
        text-align: center !important;
        flex-shrink: 0 !important;
        box-shadow: 
          0 0 60px rgba(255, 0, 85, 0.15),
          0 0 120px rgba(255, 0, 85, 0.05),
          0 25px 50px rgba(0, 0, 0, 0.5) !important;
        animation: ws-card-enter 0.5s cubic-bezier(0.16, 1, 0.3, 1) !important;
      }
      @keyframes ws-card-enter {
        from { transform: scale(0.9) translateY(20px); opacity: 0; }
        to { transform: scale(1) translateY(0); opacity: 1; }
      }
      .ws-shield-icon {
        width: 56px !important;
        height: 56px !important;
        margin: 0 auto 14px !important;
        background: linear-gradient(135deg, #ff0055, #ff4444) !important;
        border-radius: 50% !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        box-shadow: 0 0 30px rgba(255, 0, 85, 0.4) !important;
        animation: ws-pulse-ring 2s ease-in-out infinite !important;
      }
      @keyframes ws-pulse-ring {
        0%, 100% { box-shadow: 0 0 20px rgba(255, 0, 85, 0.4); }
        50% { box-shadow: 0 0 40px rgba(255, 0, 85, 0.7); }
      }
      .ws-shield-icon svg {
        width: 28px !important;
        height: 28px !important;
        fill: white !important;
      }
      .ws-title {
        color: #ff3366 !important;
        font-size: 22px !important;
        font-weight: 800 !important;
        margin: 0 0 6px 0 !important;
        letter-spacing: 0.5px !important;
        text-transform: uppercase !important;
        text-shadow: 0 0 20px rgba(255, 0, 85, 0.3) !important;
      }
      .ws-subtitle {
        color: #ff8899 !important;
        font-size: 13px !important;
        margin: 0 0 16px 0 !important;
        font-weight: 500 !important;
        letter-spacing: 0.3px !important;
      }
      .ws-url-box {
        background: rgba(255, 0, 85, 0.08) !important;
        border: 1px solid rgba(255, 0, 85, 0.25) !important;
        border-radius: 10px !important;
        padding: 10px 14px !important;
        margin-bottom: 14px !important;
        word-break: break-all !important;
        max-height: 80px !important;
        overflow-y: auto !important;
      }
      .ws-url-label {
        color: #888 !important;
        font-size: 10px !important;
        text-transform: uppercase !important;
        letter-spacing: 1.5px !important;
        margin: 0 0 4px 0 !important;
      }
      .ws-url-text {
        color: #ff6688 !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        margin: 0 !important;
        font-family: 'Consolas', 'Courier New', monospace !important;
      }
      .ws-signals {
        text-align: left !important;
        background: rgba(255, 255, 255, 0.03) !important;
        border: 1px solid rgba(255, 255, 255, 0.06) !important;
        border-radius: 10px !important;
        padding: 10px 14px !important;
        margin-bottom: 18px !important;
        max-height: 80px !important;
        overflow-y: auto !important;
      }
      .ws-signals-title {
        color: #888 !important;
        font-size: 11px !important;
        text-transform: uppercase !important;
        letter-spacing: 1.5px !important;
        margin: 0 0 10px 0 !important;
      }
      .ws-signals ul {
        list-style: none !important;
        padding: 0 !important;
        margin: 0 !important;
      }
      .ws-signals li {
        color: #ccc !important;
        font-size: 13px !important;
        padding: 4px 0 4px 18px !important;
        position: relative !important;
        line-height: 1.4 !important;
      }
      .ws-signals li::before {
        content: "⚡" !important;
        position: absolute !important;
        left: 0 !important;
        color: #ff5577 !important;
      }
      .ws-btn-row {
        display: flex !important;
        gap: 14px !important;
        justify-content: center !important;
      }
      .ws-btn {
        padding: 14px 32px !important;
        border-radius: 12px !important;
        font-size: 15px !important;
        font-weight: 700 !important;
        cursor: pointer !important;
        border: none !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        transition: all 0.25s ease !important;
      }
      .ws-btn-leave {
        background: linear-gradient(135deg, #ff0055, #cc0044) !important;
        color: white !important;
        box-shadow: 0 4px 20px rgba(255, 0, 85, 0.3) !important;
      }
      .ws-btn-leave:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 30px rgba(255, 0, 85, 0.5) !important;
        background: linear-gradient(135deg, #ff2266, #dd1155) !important;
      }
      .ws-btn-continue {
        background: transparent !important;
        color: #666 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
      }
      .ws-btn-continue:hover {
        color: #999 !important;
        border-color: rgba(255, 255, 255, 0.2) !important;
        background: rgba(255, 255, 255, 0.03) !important;
      }
      .ws-powered {
        color: #444 !important;
        font-size: 11px !important;
        margin: 20px 0 0 0 !important;
        letter-spacing: 0.5px !important;
      }
    `;
    document.head.appendChild(styleEl);

    // Build overlay
    const overlay = document.createElement("div");
    overlay.id = OVERLAY_ID;
    overlay.innerHTML = `
      <div class="ws-warning-card">
        <div class="ws-shield-icon">
          <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v2h-2V7zm0 4h2v6h-2v-6z"/>
          </svg>
        </div>
        <h1 class="ws-title">Unsafe Website Detected!</h1>
        <p class="ws-subtitle">WebShield has identified this site as potentially dangerous</p>
        
        <div class="ws-url-box">
          <p class="ws-url-label">Flagged URL</p>
          <p class="ws-url-text">${escapeHtml(result.url || window.location.href)}</p>
        </div>

        <div class="ws-signals">
          <p class="ws-signals-title">Detection Signals</p>
          <ul>${signalsHtml || "<li>Matched known phishing database entry</li>"}</ul>
        </div>

        <div class="ws-btn-row">
          <button class="ws-btn ws-btn-leave" id="ws-leave-btn">← Leave Site</button>
          <button class="ws-btn ws-btn-continue" id="ws-continue-btn">Continue Anyway</button>
        </div>
        
        <p class="ws-powered">Protected by WebShield Threat Intelligence</p>
      </div>
    `;
    document.body.appendChild(overlay);

    // Trigger visibility animation
    requestAnimationFrame(() => {
      overlay.classList.add("ws-visible");
    });

    // Button handlers
    document.getElementById("ws-leave-btn").addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "leave_site" });
    });

    document.getElementById("ws-continue-btn").addEventListener("click", () => {
      removeOverlay();
    });
  }

  /**
   * Escape HTML characters to prevent XSS in injected content.
   */
  function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str || ""));
    return div.innerHTML;
  }

  // ─── Message Listener ──────────────────────────────────────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "webshield_scan_result" && message.result) {
      const result = message.result;

      if (result.risk_score >= UNSAFE_THRESHOLD) {
        injectOverlay(result);
      } else {
        removeOverlay();
      }

      sendResponse({ received: true });
    }
  });
})();
