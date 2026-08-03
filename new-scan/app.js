import { auth, onAuthStateChanged, signOut } from '../js/firebase.js';

// DOM Elements
const userDisplay = document.getElementById("user-display");
const logoutBtn = document.getElementById("logout-btn");
const themeToggle = document.getElementById("theme-toggle");
const startScanBtn = document.getElementById("start-scan-btn");
const targetInput = document.getElementById("target-input");
const terminalOutput = document.getElementById("terminal-output");
const terminalWindow = document.getElementById("terminal-window");
const terminalStatus = document.getElementById("terminal-status");
const loader = document.getElementById("scan-loader");
const resultsSection = document.getElementById("results-section");

const API_BASE_URL = window.API_BASE_URL;
let currentUser = null;
let idToken = null;

onAuthStateChanged(auth, async (user) => {
  if (user) {
    currentUser = user;
    userDisplay.textContent = user.email.split('@')[0].toUpperCase();
    idToken = await user.getIdToken();
  } else {
    window.location.replace('../login/index.html');
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await signOut(auth);
    window.location.replace('../index.html');
  } catch (error) {
    console.error("Logout failed", error);
  }
});

themeToggle.addEventListener("click", () => {
  const currentTheme = document.documentElement.getAttribute("data-theme");
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("theme", newTheme);
  themeToggle.textContent = `THEME: ${newTheme.toUpperCase()}`;
});
themeToggle.textContent = `THEME: ${(document.documentElement.getAttribute("data-theme") || "dark").toUpperCase()}`;

function appendToTerminal(text) {
  const span = document.createElement("span");
  span.textContent = text + "\n";
  terminalOutput.appendChild(span);
  terminalWindow.scrollTop = terminalWindow.scrollHeight;
}

startScanBtn.addEventListener("click", async () => {
  let target = targetInput.value.trim();
  
  // Clean URL to just get domain/IP
  target = target.replace(/^https?:\/\//, '');
  target = target.split('/')[0];
  
  if (!target) {
    alert("Please enter a valid target.");
    return;
  }

  if (!idToken && currentUser) {
    idToken = await currentUser.getIdToken(true);
  } else if (!currentUser) {
    alert("Authentication error.");
    return;
  }

  // UI Setup
  startScanBtn.disabled = true;
  loader.classList.remove("hidden");
  terminalStatus.textContent = "INITIALIZING";
  terminalOutput.innerHTML = `> Establishing secure connection...\n> Target locked: ${target}\n\n`;
  resultsSection.classList.add("hidden");

  try {
    // 1. POST to start scan
    const startRes = await fetch(`${API_BASE_URL}/scan/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${idToken}`
      },
      body: JSON.stringify({ target })
    });

    if (!startRes.ok) throw new Error("Failed to start scan");

    const startData = await startRes.json();
    const scanId = startData.scan_id;

    // 2. Stream output
    terminalStatus.textContent = "SCANNING";
    await streamScanOutput(scanId, idToken);

    // 3. Fetch structured results
    terminalStatus.textContent = "COMPLETED";
    await fetchAndDisplayResults(scanId, idToken);

  } catch (error) {
    appendToTerminal(`[ERROR] ${error.message}`);
    terminalStatus.textContent = "FAILED";
  } finally {
    startScanBtn.disabled = false;
    loader.classList.add("hidden");
  }
});

async function streamScanOutput(scanId, token) {
  const response = await fetch(`${API_BASE_URL}/scan/stream/${scanId}`, {
    method: 'GET',
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "text/event-stream"
    }
  });

  if (!response.ok) throw new Error(`Streaming failed: ${response.statusText}`);

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = '';

  while (true) {
    const { value, done } = await reader.read();

    if (done) {
      if (buffer) processSSE(buffer);
      break;
    }

    buffer += decoder.decode(value, { stream: true });
    let lines = buffer.split('\n');
    buffer = lines.pop(); // keep last incomplete line in buffer

    for (let line of lines) {
      processSSE(line);
    }
  }
}

function processSSE(line) {
  if (line.startsWith("data: ")) {
    let textContent = line.replace("data: ", "");
    if (textContent.includes('{"status": "completed"}')) return;
    if (textContent !== "null" && textContent.trim() !== "") {
      appendToTerminal(textContent);
    }
  }
}

async function fetchAndDisplayResults(scanId, token) {
  const res = await fetch(`${API_BASE_URL}/scan/${scanId}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  if (!res.ok) return;

  const data = await res.json();
  const results = data.results;

  // Clear previous results and ensure they are visible for population
  const resetCard = (id) => {
    const el = document.getElementById(id);
    el.innerHTML = "";
    el.parentElement.classList.remove("hidden");
  };

  resetCard("res-ips");
  resetCard("res-whois");
  resetCard("res-emails");
  resetCard("res-subdomains");
  resetCard("res-ports");
  resetCard("res-ai");

  results.forEach(r => {
    const parsed = r.parsed_data;
    
    // AI Explanation doesn't need parsed data object check if raw_output exists
    if (r.type === 'ai_explanation' && r.raw_output) {
      document.getElementById("res-ai").innerHTML = r.raw_output.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return;
    }

    if (!parsed) return;

    if (r.type === 'nslookup') {
      const ips = parsed.ip_addresses || [];
      const mx = parsed.mx_records || [];
      const ns = parsed.ns_records || [];
      const names = parsed.names || [];
      const servers = parsed.servers || [];
      const aliases = parsed.aliases || [];

      names.forEach(name => document.getElementById("res-ips").innerHTML += `<li><span class='text-accent'>Name:</span> ${name}</li>`);
      ips.forEach(ip => document.getElementById("res-ips").innerHTML += `<li><span class='text-accent'>IP:</span> ${ip}</li>`);
      if (servers.length > 0) servers.forEach(s => document.getElementById("res-ips").innerHTML += `<li><span class='text-muted'>Server:</span> ${s}</li>`);
      if (aliases.length > 0) aliases.forEach(a => document.getElementById("res-ips").innerHTML += `<li><span class='text-muted'>Alias:</span> ${a}</li>`);
      if (mx.length > 0) mx.forEach(m => document.getElementById("res-ips").innerHTML += `<li><span class='text-muted'>MX:</span> ${m}</li>`);
      if (ns.length > 0) ns.forEach(n => document.getElementById("res-ips").innerHTML += `<li><span class='text-muted'>NS:</span> ${n}</li>`);
    }
    else if (r.type === 'whois') {
      // Only show whois if there's actual data beyond 'Unknown'
      if (parsed.registrar && parsed.registrar !== 'Unknown') {
        document.getElementById("res-whois").innerHTML = `
                  <div class="data-item"><span class="label">Registrar:</span> ${parsed.registrar || 'N/A'}</div>
                  <div class="data-item"><span class="label">Created:</span> ${parsed.creation_date || 'N/A'}</div>
                  <div class="data-item"><span class="label">Expires:</span> ${parsed.expiry_date || 'N/A'}</div>
                  <div class="data-item"><span class="label">Organization:</span> ${parsed.organization || 'N/A'}</div>
                  <div class="data-item"><span class="label">Owner:</span> ${parsed.registrant_name || 'N/A'}</div>
                  <div class="data-item"><span class="label">Email:</span> ${parsed.email || 'N/A'}</div>
              `;
      }
    }
    else if (r.type === 'theHarvester') {
      const emails = parsed.emails || [];
      const subs = parsed.subdomains || [];
      emails.forEach(e => document.getElementById("res-emails").innerHTML += `<li>${e}</li>`);
      subs.forEach(s => document.getElementById("res-subdomains").innerHTML += `<li>${s}</li>`);
    }
    else if (r.type === 'nmap') {
      const ports = parsed.ports || [];
      ports.forEach(p => {
        let vulnHtml = '';
        if (p.vulnerabilities && p.vulnerabilities.length > 0) {
          vulnHtml = `<div style="font-size: 0.70rem; margin-left: 1.5rem; margin-top: 0.5rem; color: #ff6b6b; font-family: monospace;">
              <strong>Vulnerabilities Found <span style="font-size: 0.6rem; color: #888;">(${p.vulnerabilities.length})</span>:</strong>
              <div style="max-height: 200px; overflow-y: auto; margin-top: 0.4rem; padding-right: 5px; border: 1px solid rgba(255,107,107,0.2); border-radius: 4px; background: rgba(0,0,0,0.2);">
                <ul style="padding-left: 0.5rem; margin: 0.5rem 0; list-style-type: none;">
                  ${p.vulnerabilities.map(v => `<li style="margin-bottom: 0.3rem; padding-bottom: 0.3rem; border-bottom: 1px dashed rgba(255,107,107,0.1); word-break: break-word;">${v.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</li>`).join('')}
                </ul>
              </div>
          </div>`;
        }
        document.getElementById("res-ports").innerHTML += `
                      <li style="font-size: 0.85rem; margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(255,255,255,0.1);">
                          <span class="text-accent">${p.port}</span> | 
                          <span class="text-muted">${p.service}</span>
                          <div style="font-size: 0.75rem; margin-left:1.5rem; color: #888;">${p.version}</div>
                          ${vulnHtml}
                      </li>`;
      });
    }
  });

  // Hide any cards that have no content
  const checkAndHide = (id) => {
    const el = document.getElementById(id);
    if (!el.innerHTML.trim()) {
      el.parentElement.classList.add("hidden");
    }
  };

  checkAndHide("res-ips");
  checkAndHide("res-whois");
  checkAndHide("res-emails");
  checkAndHide("res-subdomains");
  checkAndHide("res-ports");
  checkAndHide("res-ai");

  resultsSection.classList.remove("hidden");
}
