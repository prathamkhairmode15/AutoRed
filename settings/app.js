import { auth, onAuthStateChanged, signOut } from '../js/firebase.js';

const API_BASE_URL = window.API_BASE_URL;
const userDisplay = document.getElementById("user-display");
const logoutBtn = document.getElementById("logout-btn");
const themeToggle = document.getElementById("theme-toggle");

// Settings Elements
const portScanMode = document.getElementById("port-scan-mode");
const vulnScriptsToggle = document.getElementById("vuln-scripts-toggle");
const scanTimeout = document.getElementById("scan-timeout");
const terminalFontSize = document.getElementById("terminal-font-size");
const themeSelect = document.getElementById("theme-select");
const profileEmail = document.getElementById("profile-email");
const profileUid = document.getElementById("profile-uid");
const profileScans = document.getElementById("profile-scans");
const saveBtn = document.getElementById("save-btn");
const saveStatus = document.getElementById("save-status");
const exportBtn = document.getElementById("export-btn");
const clearBtn = document.getElementById("clear-btn");

let currentUser = null;
let idToken = null;

onAuthStateChanged(auth, async (user) => {
  if (user) {
    currentUser = user;
    userDisplay.textContent = user.email.split('@')[0].toUpperCase();
    idToken = await user.getIdToken();
    loadSettings();
    loadScanCount();
  } else {
    window.location.replace('../login/index.html');
  }
});

logoutBtn.addEventListener('click', async () => {
  await signOut(auth);
  window.location.replace('../index.html');
});

// Theme toggle (top bar)
themeToggle.addEventListener("click", () => {
  const currentTheme = document.documentElement.getAttribute("data-theme");
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  applyTheme(newTheme);
});
themeToggle.textContent = `THEME: ${(document.documentElement.getAttribute("data-theme") || "dark").toUpperCase()}`;

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
  themeToggle.textContent = `THEME: ${theme.toUpperCase()}`;
  themeSelect.value = theme;
}

// Theme select (settings card) — sync with top bar toggle
themeSelect.value = document.documentElement.getAttribute("data-theme") || "dark";
themeSelect.addEventListener("change", () => {
  applyTheme(themeSelect.value);
});

// Load Settings from API
async function loadSettings() {
  try {
    const res = await fetch(`${API_BASE_URL}/settings`, {
      headers: { "Authorization": `Bearer ${idToken}` }
    });
    if (!res.ok) return;

    const settings = await res.json();

    portScanMode.value = settings.port_scan_mode || "fast";
    vulnScriptsToggle.checked = (settings.enable_vuln_scripts || "true") === "true";
    scanTimeout.value = settings.scan_timeout || 300;
    terminalFontSize.value = settings.terminal_font_size || 14;
    profileEmail.textContent = settings.email || "Unknown";
    profileUid.textContent = settings.user_id || "—";

  } catch (err) {
    console.error("Failed to load settings:", err);
  }
}

// Load scan count
async function loadScanCount() {
  try {
    const res = await fetch(`${API_BASE_URL}/scans`, {
      headers: { "Authorization": `Bearer ${idToken}` }
    });
    if (!res.ok) return;
    const data = await res.json();
    const scans = data.scans || data;
    profileScans.textContent = Array.isArray(scans) ? scans.length : 0;
  } catch (err) {
    profileScans.textContent = "—";
  }
}

// Save Settings
saveBtn.addEventListener("click", async () => {
  saveBtn.disabled = true;
  saveBtn.textContent = "Saving...";
  saveStatus.textContent = "";

  try {
    if (!idToken && currentUser) {
      idToken = await currentUser.getIdToken(true);
    }

    const payload = {
      port_scan_mode: portScanMode.value,
      enable_vuln_scripts: vulnScriptsToggle.checked ? "true" : "false",
      scan_timeout: parseInt(scanTimeout.value) || 300,
      terminal_font_size: parseInt(terminalFontSize.value) || 14
    };

    const res = await fetch(`${API_BASE_URL}/settings`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${idToken}`
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Failed to save");

    saveStatus.textContent = "✓ Settings saved successfully";
    saveStatus.className = "save-status success";

    // Also save theme to localStorage
    localStorage.setItem("terminal_font_size", payload.terminal_font_size);

  } catch (err) {
    saveStatus.textContent = "✗ Failed to save settings";
    saveStatus.className = "save-status error";
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = "Save All Settings";

    // Fade out status after 3 seconds
    setTimeout(() => {
      saveStatus.style.opacity = "0";
      setTimeout(() => {
        saveStatus.textContent = "";
        saveStatus.style.opacity = "1";
      }, 500);
    }, 3000);
  }
});

// Export Data
exportBtn.addEventListener("click", async () => {
  exportBtn.disabled = true;
  exportBtn.textContent = "Exporting...";

  try {
    if (!idToken && currentUser) {
      idToken = await currentUser.getIdToken(true);
    }

    const res = await fetch(`${API_BASE_URL}/scans/export`, {
      headers: { "Authorization": `Bearer ${idToken}` }
    });
    if (!res.ok) throw new Error("Export failed");

    const data = await res.json();

    // Trigger download
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `autored_export_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

  } catch (err) {
    alert("Export failed: " + err.message);
  } finally {
    exportBtn.disabled = false;
    exportBtn.textContent = "Export JSON";
  }
});

// Clear All Data
clearBtn.addEventListener("click", async () => {
  const confirmed = confirm(
    "⚠️ WARNING: This will permanently delete ALL your scan history, results, and vulnerability data.\n\nThis action CANNOT be undone.\n\nAre you sure you want to proceed?"
  );

  if (!confirmed) return;

  clearBtn.disabled = true;
  clearBtn.textContent = "Clearing...";

  try {
    if (!idToken && currentUser) {
      idToken = await currentUser.getIdToken(true);
    }

    const res = await fetch(`${API_BASE_URL}/scans/clear`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${idToken}` }
    });
    if (!res.ok) throw new Error("Failed to clear");

    const result = await res.json();
    alert(result.message);

    // Refresh stats
    profileScans.textContent = "0";

  } catch (err) {
    alert("Clear failed: " + err.message);
  } finally {
    clearBtn.disabled = false;
    clearBtn.textContent = "Clear All Data";
  }
});
