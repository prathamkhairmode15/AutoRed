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

const API_BASE_URL = "http://localhost:8000/api";
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
  const target = targetInput.value.trim();
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

    document.getElementById("res-ips").innerHTML = "";
    document.getElementById("res-whois").innerHTML = "";
    document.getElementById("res-emails").innerHTML = "";
    document.getElementById("res-subdomains").innerHTML = "";

    results.forEach(r => {
        const parsed = r.parsed_data;
        if (!parsed) return;

        if (r.type === 'nslookup') {
            const ips = parsed.ip_addresses || [];
            if (ips.length === 0) document.getElementById("res-ips").innerHTML = "<li>No IPs resolved</li>";
            else ips.forEach(ip => document.getElementById("res-ips").innerHTML += `<li>${ip}</li>`);
        }
        else if (r.type === 'whois') {
            document.getElementById("res-whois").innerHTML = `
                <div>Registrar: ${parsed.registrar || 'N/A'}</div>
                <div>Created: ${parsed.creation_date || 'N/A'}</div>
            `;
        }
        else if (r.type === 'theHarvester') {
            const emails = parsed.emails || [];
            const subs = parsed.subdomains || [];
            if (emails.length === 0) document.getElementById("res-emails").innerHTML = "<li>No emails found</li>";
            else emails.forEach(e => document.getElementById("res-emails").innerHTML += `<li>${e}</li>`);
            if (subs.length === 0) document.getElementById("res-subdomains").innerHTML = "<li>No subdomains found</li>";
            else subs.forEach(s => document.getElementById("res-subdomains").innerHTML += `<li>${s}</li>`);
        }
    });

    resultsSection.classList.remove("hidden");
}
