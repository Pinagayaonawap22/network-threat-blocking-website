document.getElementById("scanButton").addEventListener("click", () => {
    const scanResultsDiv = document.getElementById("scanResults");
    scanResultsDiv.innerHTML = "<p>🔍 Scanning... please wait.</p>";

    fetch("/deep_scan")
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                scanResultsDiv.innerHTML = `<p style="color:red;">❌ Error: ${data.error}</p>`;
                return;
            }

            // ✅ Render results (your existing code)
            let html = `<h3>${data.message}</h3>`;

            // Local Scan Section
            html += `<h4>📡 Local Network Devices:</h4>`;
            if (Array.isArray(data.local_scan) && data.local_scan.length > 0) {
                data.local_scan.forEach(device => {
                    html += `<h5>🔹 ${device.ip}</h5><ul>`;
                    if (device.ports && device.ports.length > 0) {
                        device.ports.forEach(p => {
                            html += `<li>
                                Port ${p.port} (${p.service}) → 
                                Risk: <strong>${p.risk}</strong> | 
                                Advice: ${p.advice} <br>
                                Usability: ${p.usability || "N/A"} | 
                                Vulnerability: ${p.vulnerability_status || "N/A"}
                            </li>`;
                        });
                    } else {
                        html += `<li>No open ports</li>`;
                    }
                    html += `</ul>`;
                });
            } else {
                html += `<p>No devices found.</p>`;
            }

            // Public Scan Section
            html += `<h4>🌍 Public IP (${data.public_scan.ip}):</h4>`;
            if (Array.isArray(data.public_scan.ports) && data.public_scan.ports.length > 0) {
                html += `<ul>`;
                data.public_scan.ports.forEach(p => {
                    html += `<li>
                        Port ${p.port} (${p.service}) → 
                        Risk: <strong>${p.risk}</strong> | 
                        Advice: ${p.advice} <br>
                        Usability: ${p.usability || "N/A"} | 
                        Vulnerability: ${p.vulnerability_status || "N/A"}
                    </li>`;
                });
                html += `</ul>`;
            } else {
                html += `<p>No open ports found.</p>`;
            }
            
            //scan summary
            html += `<h4>🛡️ Scan Summary:</h4>`
            html += `<p>Total Local Devices: ${data.local_scan.length}</p>`
            html += `<p>Public IP: ${data.public_scan.ip}</p>`
            const totalLocalPorts = data.local_scan.reduce((sum, device) => sum + (
                Array.isArray(device.ports) ? device.ports.length : 0
                ), 0);  
            html += `<p>Total Open Local Ports: ${totalLocalPorts}</p>`
            html += `<p>Total Open Public Ports: ${data.public_scan.ports.length}</p>`
            html += `<p>Scan completed at: ${new Date().toLocaleString()}</p>`
            

            // Update the scan results div
            scanResultsDiv.innerHTML = html;
            loadThreats();
            loadBlocks();
            loadStats();
            loadSystemMetrics();
        })
        .catch(err => {
            scanResultsDiv.innerHTML = `<p style="color:red;">❌ Fetch error: ${err}</p>`;
        });
});

document.getElementById("patchButton").addEventListener("click", () => {
    const scanResultsDiv = document.getElementById("scanResults");
    scanResultsDiv.innerHTML = "<p>⚙️ Applying patches... please wait.</p>";

    fetch("/apply_patches", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                scanResultsDiv.innerHTML = `<p style="color:red;">❌ Error: ${data.error}</p>`;
                return;
            }

            let html = `<h3>${data.message}</h3><ul>`;
            data.actions.forEach(action => {
                html += `<li>${action}</li>`;
            });
            html += "</ul>";
            scanResultsDiv.innerHTML = html;
        })
        .catch(err => {
            scanResultsDiv.innerHTML = `<p style="color:red;">❌ Fetch error: ${err}</p>`;
        });
});

document.getElementById("verifyButton").addEventListener("click", () => {
    const scanResultsDiv = document.getElementById("scanResults");
    scanResultsDiv.innerHTML = "<p>🔄 Verifying patches... please wait.</p>";

    fetch("/verify_patches", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                scanResultsDiv.innerHTML = `<p style="color:red;">❌ Error: ${data.error}</p>`;
                return;
            }

            let html = `<h3>${data.message}</h3>`;
            html += `<h4>✅ Fixed Issues:</h4><ul>`;
            data.fixed.forEach(f => { html += `<li>${f}</li>`; });
            html += `</ul>`;

            html += `<h4>⚠️ Remaining Issues:</h4><ul>`;
            data.remaining.forEach(r => { html += `<li>${r}</li>`; });
            html += `</ul>`;

            scanResultsDiv.innerHTML = html;
        })
        .catch(err => {
            scanResultsDiv.innerHTML = `<p style="color:red;">❌ Fetch error: ${err}</p>`;
        });
});

    // Button click handlers with enhanced feedback
    document.querySelectorAll('.btn').forEach(button => {
    button.addEventListener('click', function(e) {
        // Create ripple effect
        const ripple = document.createElement('span');
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        left: ${x}px;
        top: ${y}px;
        background: rgba(255, 255, 255, 0.3);
        border-radius: 50%;
        pointer-events: none;
        animation: ripple 0.6s ease-out;
        `;
        
        button.style.position = 'relative';
        button.style.overflow = 'hidden';
        button.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);

        // Simulate action feedback
        const buttonText = button.textContent;
        if (button.classList.contains('primary') && buttonText.includes('Block')) {
        button.innerHTML = '✓ Blocking...';
        setTimeout(() => {
            button.innerHTML = buttonText;
        }, 2000);
        } else if (buttonText.includes('Refresh')) {
        button.innerHTML = '↻ Refreshing...';
        setTimeout(() => {
            button.innerHTML = buttonText;
        }, 1500);
        }
    });
    });

    // Add CSS for ripple animation
    const style = document.createElement('style');
    style.textContent = `
    @keyframes ripple {
        0% {
        transform: scale(0);
        opacity: 1;
        }
        100% {
        transform: scale(2);
        opacity: 0;
        }
    }
    `;
    document.head.appendChild(style);

    // Animate progress bars
    const progressBars = document.querySelectorAll('.progress-fill');
    progressBars.forEach(bar => {
    const width = bar.style.width;
    bar.style.width = '0%';
    setTimeout(() => {
        bar.style.width = width;
    }, 500);
    });

    // Update timestamp every minute
    setInterval(() => {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit' 
    });
    
    // Update any "Last sync" or timestamp elements
    document.querySelectorAll('.stat-trend').forEach(el => {
        if (el.textContent.includes('sync')) {
        const seconds = Math.floor(Math.random() * 60);
        el.innerHTML = `
            <div class="loading-spinner"></div>
            Last sync: ${seconds}s ago
        `;
        }
    });
    }, 60000);

  var map = L.map('map').setView([20, 0], 2);

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
  }).addTo(map);

  async function loadThreats() {
    try {
      let res = await fetch("/api/threats");
      let threats = await res.json();
      console.log("Threats received:", threats); // debug log
      threats.forEach(t => {
        let marker = L.marker([t.lat, t.lon]).addTo(map);
        marker.bindPopup(`
          <b>IP:</b> ${t.ip}<br>
          <b>Country:</b> ${t.country}<br>
          <b>City:</b> ${t.city}<br>
          <b>Service:</b> ${t.service}<br>
          <b>Port:</b> ${t.port}<br>
          <b>Risk:</b> ${t.risk}
        `);
      });
    } catch (err) {
      console.error("Error loading threats:", err);
    }
  }

async function loadBlocks() {
  try {
    const res = await fetch("/api/blocks");
    const blocks = await res.json();
    const tbody = document.querySelector(".data-table tbody");
    tbody.innerHTML = "";

    blocks.forEach(b => {
      // format since (timestamp) nicely
      const since = new Date(b.timestamp).toLocaleString();
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${b.ip}</td>
        <td>${since}</td>
        <td><span class="badge ${b.risk ? b.risk.toLowerCase() : ''}">${b.risk || 'Unknown'}</span></td>
        <td>${b.action}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load blocks:", err);
  }
}

async function loadStats() {
  try {
    let res = await fetch("/api/stats");
    let stats = await res.json();

    document.querySelector("#stat-critical").textContent = stats.critical_threats;
    document.querySelector("#stat-blocked").textContent = stats.blocked_ips;
    document.querySelector("#stat-pending").textContent = stats.pending_review;
    document.querySelector("#stat-health").textContent = stats.system_health;
  } catch (err) {
    console.error("Error loading stats:", err);
  }
}

async function loadSystemMetrics() {
  try {
    const res = await fetch("/api/system_metrics");
    const data = await res.json();

    document.getElementById("cpu-usage").textContent = `${data.cpu_usage}%`;
    document.getElementById("cpu-bar").style.width = `${data.cpu_usage}%`;

    document.getElementById("memory-usage").textContent = `${data.memory_usage}%`;
    document.getElementById("memory-bar").style.width = `${data.memory_usage}%`;

    document.getElementById("disk-usage").textContent = `${data.disk_usage}%`;
    document.getElementById("disk-bar").style.width = `${data.disk_usage}%`;

    document.getElementById("network-traffic").textContent = 
      `${data.network_sent} MB sent / ${data.network_recv} MB recv`;
  } catch (err) {
    console.error("Error loading system metrics:", err);
  }
}

