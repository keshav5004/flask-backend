document.addEventListener("DOMContentLoaded", () => {
    const riskCtx = document.getElementById("riskChart");
    const scanCtx = document.getElementById("scanChart");

    if (!riskCtx || !scanCtx) return;

    // Fetch stats data from API
    fetch("/api/stats")
        .then(response => response.json())
        .then(data => {
            renderCharts(data);
        })
        .catch(err => {
            console.error("Failed to load dashboard stats chart data", err);
        });

    const renderCharts = (stats) => {
        // 1. Risk Level Doughnut Chart
        const riskLabels = ["Safe", "Low Risk", "Medium Risk", "High Risk", "Malicious"];
        const riskCounts = [
            stats.risk_distribution.safe || 0,
            stats.risk_distribution.low || 0,
            stats.risk_distribution.medium || 0,
            stats.risk_distribution.high || 0,
            stats.risk_distribution.malicious || 0
        ];

        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: riskLabels,
                datasets: [{
                    data: riskCounts,
                    backgroundColor: [
                        '#00f0ff', // Safe
                        '#00ff66', // Low
                        '#ffaa00', // Medium
                        '#ff5500', // High
                        '#ff0055'  // Malicious
                    ],
                    borderColor: '#0b0f19',
                    borderWidth: 3,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#9ca3af',
                            font: {
                                family: 'Outfit',
                                size: 12
                            },
                            padding: 15
                        }
                    }
                },
                cutout: '70%'
            }
        });

        // 2. Daily Scans Trend Line Chart
        const dailyLabels = stats.daily_scans.map(item => {
            const date = new Date(item.day);
            return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        });
        const dailyData = stats.daily_scans.map(item => item.count);

        // Fallback for trend chart if empty
        const finalLabels = dailyLabels.length ? dailyLabels : ["Today"];
        const finalData = dailyData.length ? dailyData : [stats.total_scanned];

        new Chart(scanCtx, {
            type: 'line',
            data: {
                labels: finalLabels,
                datasets: [{
                    label: 'Scan History (Last 7 Days)',
                    data: finalData,
                    fill: true,
                    backgroundColor: 'rgba(0, 240, 255, 0.05)',
                    borderColor: '#00f0ff',
                    borderWidth: 3,
                    pointBackgroundColor: '#00f0ff',
                    pointBorderColor: '#0b0f19',
                    pointBorderWidth: 2,
                    pointRadius: 6,
                    pointHoverRadius: 8,
                    tension: 0.35
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        ticks: {
                            color: '#9ca3af',
                            font: { family: 'Outfit' }
                        }
                    },
                    y: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        ticks: {
                            color: '#9ca3af',
                            font: { family: 'Outfit' },
                            stepSize: 1
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    };
});
