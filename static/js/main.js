document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scan-form");
    const urlInput = document.getElementById("url-input");
    const scanBtn = document.getElementById("scan-btn");
    const scanBtnText = document.getElementById("scan-btn-text");
    const scanBtnIcon = document.getElementById("scan-btn-icon");

    // Sections
    const scannerSection = document.getElementById("scanner-section");
    const loadingSection = document.getElementById("loading-section");
    const resultsSection = document.getElementById("results-section");

    // Results elements
    const resultUrl = document.getElementById("result-url");
    const safetyBadge = document.getElementById("safety-badge");
    const safetyStatusText = document.getElementById("safety-status-text");
    const safetyMessage = document.getElementById("safety-message");
    const riskScoreValue = document.getElementById("risk-score-value");
    const riskScoreLevel = document.getElementById("risk-score-level");
    const similarityScoreVal = document.getElementById("similarity-score-val");
    const matchedDomainVal = document.getElementById("matched-domain-val");
    const detectionMethodVal = document.getElementById("detection-method-val");
    const signalList = document.getElementById("signal-list");

    // Risk Meter Dial
    const riskDialFill = document.getElementById("risk-dial-fill");

    // Color mapper helper
    const getRiskColors = (level) => {
        const colors = {
            "safe": { color: "#00f0ff", glow: "rgba(0, 240, 255, 0.3)" },
            "low": { color: "#00ff66", glow: "rgba(0, 255, 102, 0.3)" },
            "medium": { color: "#ffaa00", glow: "rgba(255, 170, 0, 0.3)" },
            "high": { color: "#ff5500", glow: "rgba(255, 85, 0, 0.3)" },
            "malicious": { color: "#ff0055", glow: "rgba(255, 0, 85, 0.3)" }
        };
        return colors[level.toLowerCase()] || colors["safe"];
    };

    if (scanForm) {
        scanForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const urlToScan = urlInput.value.trim();
            if (!urlToScan) return;

            // Trigger Loading state animation
            if (scannerSection) {
                scannerSection.style.opacity = "0.5";
            }
            scanBtn.disabled = true;
            scanBtnText.textContent = "Scanning...";
            scanBtnIcon.className = "fas fa-spinner fa-spin";

            // If we are on the index page, we can show the loading spinner section and hide the hero
            if (loadingSection) {
                loadingSection.classList.remove("d-none");
                // Scroll to loading
                loadingSection.scrollIntoView({ behavior: "smooth" });
            }

            try {
                const response = await fetch("/scan", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ url: urlToScan })
                });

                if (!response.ok) {
                    throw new Error("Scan execution failed.");
                }

                const result = await response.json();

                // Wait 1.2s to simulate deep threat inspection analysis
                setTimeout(() => {
                    if (loadingSection) {
                        loadingSection.classList.add("d-none");
                    }
                    if (scannerSection) {
                        scannerSection.style.opacity = "1";
                    }
                    scanBtn.disabled = false;
                    scanBtnText.textContent = "Scan URL";
                    scanBtnIcon.className = "fas fa-shield-alt";

                    // Update UI with result
                    displayScanResult(result);
                }, 1200);

            } catch (err) {
                console.error(err);
                alert("Error scanning URL. Please ensure the backend is running and input is correct.");
                if (scannerSection) {
                    scannerSection.style.opacity = "1";
                }
                scanBtn.disabled = false;
                scanBtnText.textContent = "Scan URL";
                scanBtnIcon.className = "fas fa-shield-alt";
                if (loadingSection) {
                    loadingSection.classList.add("d-none");
                }
            }
        });
    }

    const displayScanResult = (data) => {
        if (!resultsSection) {
            // If we're not on a page with a results section inline, redirect to results view
            window.location.href = `/scan-result?url=${encodeURIComponent(data.url)}&id=${data.scan_id}`;
            return;
        }

        // Fill data
        resultUrl.textContent = data.url;
        resultUrl.href = data.url.startsWith("http") ? data.url : `http://${data.url}`;

        // Badge & Level logic
        const riskColors = getRiskColors(data.risk_level);
        
        safetyBadge.className = `badge badge-cyber ${data.risk_level.toLowerCase()}`;
        safetyBadge.textContent = getRiskLabel(data.risk_level);
        safetyBadge.style.color = riskColors.color;
        safetyBadge.style.borderColor = riskColors.color;
        safetyBadge.style.boxShadow = `0 0 10px ${riskColors.glow}`;

        safetyStatusText.textContent = `Website Status: ${getRiskLabel(data.risk_level)}`;
        safetyMessage.textContent = data.message || `No critical threats matched in exact database lookup. Similarity score: ${(data.similarity_score * 100).toFixed(0)}%.`;

        // Risk Meter Dial (Rotation from -45deg to 135deg based on score 0-100)
        const rotationAngle = -45 + (180 * (data.risk_score / 100));
        riskDialFill.style.transform = `rotate(${rotationAngle}deg)`;
        riskDialFill.style.borderColor = riskColors.color;
        
        riskScoreValue.textContent = data.risk_score;
        riskScoreValue.style.color = riskColors.color;
        riskScoreLevel.textContent = `${getRiskLabel(data.risk_level)} Level`;
        riskScoreLevel.style.color = riskColors.color;

        // Details list
        similarityScoreVal.textContent = `${(data.similarity_score * 100).toFixed(1)}%`;
        matchedDomainVal.textContent = data.matched_domain || "N/A";
        detectionMethodVal.textContent = data.detection_method === "exact" ? "Blacklist Exact Match" : "Similarity & Typo Analysis";

        // Signals list
        signalList.innerHTML = "";
        if (data.signals && data.signals.length > 0) {
            data.signals.forEach(sig => {
                const li = document.createElement("li");
                li.className = "list-group-item bg-transparent text-light border-0 ps-0 d-flex align-items-center gap-2";
                li.innerHTML = `<i class="fas fa-exclamation-triangle" style="color: ${riskColors.color}"></i> <span>${sig}</span>`;
                signalList.appendChild(li);
            });
        } else {
            signalList.innerHTML = `<li class="list-group-item bg-transparent text-secondary border-0 ps-0">No risk signals flagged.</li>`;
        }

        // Show Results container
        resultsSection.classList.remove("d-none");
        resultsSection.scrollIntoView({ behavior: "smooth" });
    };

    const getRiskLabel = (lvl) => {
        const labels = {
            "safe": "Safe",
            "low": "Low Risk",
            "medium": "Medium Risk",
            "high": "High Risk",
            "malicious": "Malicious"
        };
        return labels[lvl.toLowerCase()] || lvl;
    };
});
