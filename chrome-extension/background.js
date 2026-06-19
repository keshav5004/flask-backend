/**
 * WebShield Chrome Extension — Background Service Worker
 * 
 * Orchestrates real-time phishing detection by:
 * 1. Listening to tab navigation and tab-switch events
 * 2. Sending the current URL to the Flask backend API
 * 3. Updating the extension badge, firing notifications, and
 *    messaging the content script to inject/remove warning overlays
 */

const API_BASE = "https://flask-backend-52nr.onrender.com";
const CHECK_ENDPOINT = `${API_BASE}/api/check`;

// Cache TTL: avoid re-scanning the same URL within 5 minutes
const CACHE_TTL_MS = 5 * 60 * 1000;

// Risk score threshold: any score >= this value is treated as unsafe
const UNSAFE_THRESHOLD = 40;

// Chrome security interstitial keywords in tab titles
const CHROME_WARNING_KEYWORDS = [
  "deceptive site",
  "dangerous site",
  "privacy error",
  "connection is not private",
  "site ahead contains",
  "phishing warning",
  "malware warning",
  "suspicious site",
  "security warning"
];

/**
 * Check if a tab title matches common Chrome security warnings.
 */
function isChromeWarningTitle(title) {
  if (!title) return false;
  const lowerTitle = title.toLowerCase();
  return CHROME_WARNING_KEYWORDS.some(keyword => lowerTitle.includes(keyword));
}

/**
 * Handle tabs where Chrome itself has flagged the page as unsafe.
 */
async function handleChromeWarning(tabId, url) {
  const chromeUnsafeResult = {
    url: url,
    status: "unsafe",
    safe: false,
    risk_score: 99,
    risk_level: "dangerous",
    detection_method: "chrome_safe_browsing",
    signals: ["Google Chrome Safe Browsing flagged this website as dangerous/suspicious."],
    message: "Google Chrome flagged this website as unsafe."
  };
  
  const cacheKey = `cache_${url}`;
  try {
    await chrome.storage.local.set({
      [cacheKey]: { result: chromeUnsafeResult, timestamp: Date.now() },
      latestResult: chromeUnsafeResult
    });
  } catch (e) {
    console.error("[WebShield] Local storage write failed:", e);
  }
  
  updateBadge(tabId, chromeUnsafeResult);
  notifyContentScript(tabId, chromeUnsafeResult);
  showPhishingNotification(url, chromeUnsafeResult);
}


// URLs we should never scan (internal browser pages)
const SKIP_PREFIXES = [
  "chrome://", "chrome-extension://", "about:", "edge://",
  "brave://", "devtools://", "view-source:", "data:", "blob:",
  "file://", "chrome-search://", "new-tab-page"
];

// Trusted domains — these (and ALL their subdomains) are always safe.
// e.g. "google.com" covers accounts.google.com, mail.google.com, etc.
const TRUSTED_DOMAINS = [
  "google.com", "google.co.in", "google.co.uk",
  "microsoft.com", "live.com", "outlook.com", "office.com",
  "apple.com", "icloud.com",
  "facebook.com", "instagram.com", "whatsapp.com",
  "amazon.com", "amazon.in",
  "github.com", "gitlab.com",
  "twitter.com", "x.com",
  "linkedin.com",
  "netflix.com",
  "paypal.com",
  "youtube.com",
  "reddit.com",
  "yahoo.com",
  "wikipedia.org",
  "stackoverflow.com",
  "dropbox.com",
  "spotify.com",
  "discord.com",
  "twitch.tv",
  "adobe.com",
  "cloudflare.com",
  "render.com",
  "vercel.app",
  "netlify.app",
  "herokuapp.com",
  "zoom.us",
  "slack.com",
];

/**
 * Extract the root domain from a URL.
 * e.g. "https://accounts.google.com/v3/signin/..." → "google.com"
 */
function getRootDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    const parts = hostname.split(".");
    // Handle two-part TLDs like .co.in, .co.uk
    if (parts.length >= 3) {
      const lastTwo = parts.slice(-2).join(".");
      const twoPartTLDs = ["co.in", "co.uk", "co.jp", "com.au", "com.br", "co.nz", "org.uk"];
      if (twoPartTLDs.includes(lastTwo)) {
        return parts.slice(-3).join(".");
      }
    }
    return parts.slice(-2).join(".");
  } catch {
    return "";
  }
}

/**
 * Check if a URL belongs to a trusted domain (including subdomains).
 */
function isTrustedDomain(url) {
  const root = getRootDomain(url);
  return TRUSTED_DOMAINS.includes(root);
}

/**
 * Determine whether a URL should be skipped (browser-internal pages).
 */
function shouldSkip(url) {
  if (!url) return true;
  return SKIP_PREFIXES.some(prefix => url.startsWith(prefix));
}

/**
 * Call the Flask backend to check a URL and return the JSON result.
 */
async function checkUrl(url) {
  try {
    const response = await fetch(
      `${CHECK_ENDPOINT}?url=${encodeURIComponent(url)}`,
      { method: "GET", headers: { "Accept": "application/json" } }
    );
    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error("[WebShield] API call failed:", error.message);
    return null;
  }
}

/**
 * Set the extension toolbar badge based on scan result.
 */
function updateBadge(tabId, result) {
  if (!result) {
    // Backend unreachable — show gray "?" badge
    chrome.action.setBadgeText({ text: "?", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#6b7280", tabId });
    return;
  }

  const isUnsafe = result.risk_score >= UNSAFE_THRESHOLD;
  if (!isUnsafe) {
    chrome.action.setBadgeText({ text: "✓", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#00cc66", tabId });
  } else {
    chrome.action.setBadgeText({ text: "⚠", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ff0055", tabId });
  }
}

/**
 * Fire a browser notification when a phishing site is detected.
 */
function showPhishingNotification(url, result) {
  chrome.notifications.create(`phishing-${Date.now()}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: "⚠ Unsafe Website Detected!",
    message: `WebShield has flagged this site as dangerous:\n${url}`,
    priority: 2
  });
}

/**
 * Send the scan result to the content script for overlay injection.
 */
function notifyContentScript(tabId, result) {
  chrome.tabs.sendMessage(tabId, {
    action: "webshield_scan_result",
    result: result
  }).catch(() => {
    // Content script may not be ready yet — this is expected on some pages
  });
}

/**
 * Main scan pipeline: check URL, update badge, notify, cache result.
 */
async function scanTab(tabId, url) {
  if (shouldSkip(url)) {
    chrome.action.setBadgeText({ text: "", tabId });
    return;
  }

  // Check if Chrome itself flagged this tab via title
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.title && isChromeWarningTitle(tab.title)) {
      await handleChromeWarning(tabId, url);
      return;
    }
  } catch (e) {
    // Tab info query might fail if tab is closed or during early load
  }

  // Trusted domains (and all their subdomains) are always safe — no API call needed
  if (isTrustedDomain(url)) {
    const safeResult = {
      url: url,
      status: "safe",
      safe: true,
      risk_score: 0,
      risk_level: "safe",
      detection_method: "trusted",
      signals: ["This is a verified and trusted website."],
      message: "Website is safe."
    };
    updateBadge(tabId, safeResult);
    notifyContentScript(tabId, safeResult);
    await chrome.storage.local.set({ latestResult: safeResult });
    return;
  }

  // Check cache first
  const cacheKey = `cache_${url}`;
  try {
    const cached = await chrome.storage.local.get(cacheKey);
    if (cached[cacheKey]) {
      const entry = cached[cacheKey];
      if (Date.now() - entry.timestamp < CACHE_TTL_MS) {
        // Use cached result
        updateBadge(tabId, entry.result);
        notifyContentScript(tabId, entry.result);
        // Store as latest for popup
        await chrome.storage.local.set({ latestResult: entry.result });
        return;
      }
    }
  } catch (e) {
    // Storage access failed — proceed with fresh scan
  }

  // Set loading badge
  chrome.action.setBadgeText({ text: "...", tabId });
  chrome.action.setBadgeBackgroundColor({ color: "#ffaa00", tabId });

  const result = await checkUrl(url);

  // Update badge
  updateBadge(tabId, result);

  if (result) {
    // Cache the result
    await chrome.storage.local.set({
      [cacheKey]: { result, timestamp: Date.now() },
      latestResult: result
    });

    // Notify content script
    notifyContentScript(tabId, result);

    // Fire browser notification for unsafe sites (risk_score >= 40)
    if (result.risk_score >= UNSAFE_THRESHOLD) {
      showPhishingNotification(url, result);
    }
  }
}


// ─── Event Listeners ─────────────────────────────────────────

/**
 * Trigger scan when a page finishes loading.
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Check if Chrome itself flagged it (via tab title)
  const title = tab.title || changeInfo.title || "";
  if (tab.url && !shouldSkip(tab.url) && isChromeWarningTitle(title)) {
    handleChromeWarning(tabId, tab.url);
    return;
  }

  if (changeInfo.status === "complete" && tab.url) {
    scanTab(tabId, tab.url);
  }
});

/**
 * Trigger scan when the user switches to a different tab.
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      scanTab(activeInfo.tabId, tab.url);
    }
  } catch (e) {
    // Tab may have been closed
  }
});

/**
 * Listen for messages from popup requesting a fresh scan.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "force_scan" && message.url) {
    // Invalidate cache for this URL
    const cacheKey = `cache_${message.url}`;
    chrome.storage.local.remove(cacheKey).then(() => {
      checkUrl(message.url).then(result => {
        if (result) {
          chrome.storage.local.set({ latestResult: result });
          // Update badge on the active tab
          chrome.tabs.query({ active: true, currentWindow: true }).then(tabs => {
            if (tabs[0]) {
              updateBadge(tabs[0].id, result);
              notifyContentScript(tabs[0].id, result);
            }
          });
        }
        sendResponse({ result });
      });
    });
    return true; // Keep message channel open for async sendResponse
  }
});
