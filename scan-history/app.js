import { auth, onAuthStateChanged, signOut } from '../js/firebase.js';

const API_BASE_URL = "http://localhost:8000/api";
const userDisplay = document.getElementById("user-display");
const logoutBtn = document.getElementById("logout-btn");
const themeToggle = document.getElementById("theme-toggle");
const tableBody = document.getElementById("history-table-body");
const modal = document.getElementById("scan-modal");
const closeModal = document.getElementById("close-modal");
const modalBody = document.getElementById("modal-body");
const modalTitle = document.getElementById("modal-title");

let currentUser = null;
let idToken = null;

onAuthStateChanged(auth, async (user) => {
  if (user) {
    currentUser = user;
    userDisplay.textContent = user.email.split('@')[0].toUpperCase();
    idToken = await user.getIdToken();
    fetchHistory();
  } else {
    window.location.replace('../login/index.html');
  }
});

logoutBtn.addEventListener('click', async () => {
    await signOut(auth);
    window.location.replace('../index.html');
});

themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
    themeToggle.textContent = `THEME: ${newTheme.toUpperCase()}`;
});
let allScans = [];
const searchInput = document.getElementById("search-input");

searchInput.addEventListener("input", () => {
    const query = searchInput.value.toLowerCase().trim();
    const filtered = query
        ? allScans.filter(s => s.target.toLowerCase().includes(query))
        : allScans;
    renderHistory(filtered);
});

async function fetchHistory() {
    try {
        const res = await fetch(`${API_BASE_URL}/scans`, {
            headers: { "Authorization": `Bearer ${idToken}` }
        });
        if (!res.ok) throw new Error("Failed to fetch history");

        const data = await res.json();
        allScans = data.scans || data;
        renderHistory(allScans);

    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#ff3b3b;">${err.message}</td></tr>`;
    }
}

function renderHistory(scans) {
    if (scans.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 2rem;">No matching scans found.</td></tr>';
        return;
    }

    tableBody.innerHTML = scans.map(scan => `
        <tr>
          <td>${scan.target}</td>
          <td style="color: ${scan.status === 'completed' ? 'var(--accent-color)' : scan.status === 'failed' ? '#ff3b3b' : '#ffcc00'}">${scan.status.toUpperCase()}</td>
          <td>${scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</td>
          <td>
            <button class="btn-primary" style="padding: 0.3rem 0.8rem; font-size: 0.7rem;" data-id="${scan.id}" data-target="${scan.target}">View Report</button>
          </td>
        </tr>
    `).join('');

    document.querySelectorAll('.btn-primary[data-id]').forEach(btn => {
        btn.addEventListener('click', (e) => openModal(e.target.dataset.id, e.target.dataset.target));
    });
}

closeModal.addEventListener('click', () => {
    modal.classList.add('hidden');
});

// Close modal when clicking outside
window.addEventListener('click', (e) => {
    if (e.target === modal) {
        modal.classList.add('hidden');
    }
});

async function openModal(scanId, target) {
    modal.classList.remove('hidden');
    modalTitle.textContent = `Intelligence Report: ${target}`;
    modalBody.innerHTML = '<p style="text-align:center; color: var(--text-secondary);">Decrypting data...</p>';

    try {
        const res = await fetch(`${API_BASE_URL}/scan/${scanId}`, {
            headers: { "Authorization": `Bearer ${idToken}` }
        });
        if (!res.ok) throw new Error("Failed to fetch scan details");
        const data = await res.json();
        
        const results = data.results;
        if (!results || results.length === 0) {
            modalBody.innerHTML = '<p style="text-align:center; color: #ff3b3b;">No parsed data found for this scan.</p>';
            return;
        }

        let html = '';
        results.forEach(r => {
            const d = r.parsed_data || {};
            html += `<div class="data-section">
                <div class="data-title">[SOURCE] ${r.type.toUpperCase()}</div>
                <div class="data-content">${formatToolData(r.type, d)}</div>
            </div>`;
        });
        
        modalBody.innerHTML = html;
    } catch (err) {
        modalBody.innerHTML = `<p style="text-align:center; color: #ff3b3b;">Error: ${err.message}</p>`;
    }
}

function formatToolData(type, d) {
    let out = '';

    if (type === 'nslookup') {
        out += renderList('Resolved Hostnames', d.names);
        out += renderList('IP Addresses', d.ip_addresses);
        out += renderList('A Records', d.a_records);
        out += renderList('AAAA Records', d.aaaa_records);
        out += renderList('MX Records (Mail Servers)', d.mx_records);
        out += renderList('NS Records (Name Servers)', d.ns_records);
        out += renderList('TXT Records', d.txt_records);
        out += renderList('DNS Servers', d.servers);
        out += renderList('Aliases', d.aliases);
    }
    else if (type === 'whois') {
        const fields = [
            ['Registrar', d.registrar],
            ['Organization', d.organization],
            ['Registrant', d.registrant_name],
            ['Email', d.email],
            ['Phone', d.phone],
            ['Created', d.creation_date],
            ['Expires', d.expiry_date],
            ['Updated', d.updated_date],
        ];
        fields.forEach(([label, val]) => {
            if (val && val !== 'Unknown') {
                out += `<span style="color:#888;">${label}:</span> ${escHtml(val)}\n`;
            }
        });
        out += renderList('Name Servers', d.name_servers);
    }
    else if (type === 'theHarvester' || type === 'theharvester') {
        out += renderList('Discovered Emails', d.emails);
        out += renderList('Discovered Subdomains', d.subdomains);
    }
    else if (type === 'nmap') {
        const ports = d.ports || [];
        if (ports.length === 0) {
            out += '<span style="color:#888;">No open ports discovered.</span>\n';
        } else {
            out += `<span style="color:var(--accent-color);">Open Ports & Services (${ports.length})</span>\n`;
            out += `<span style="color:#555;">${'─'.repeat(50)}</span>\n`;
            ports.forEach(p => {
                out += `  <span style="color:#4caf50;">▸</span> Port <span style="color:var(--accent-color);">${escHtml(p.port)}</span>`;
                out += ` — ${escHtml(p.service || 'unknown')}`;
                if (p.version) out += ` <span style="color:#888;">(${escHtml(p.version)})</span>`;
                out += '\n';

                const vulns = p.vulnerabilities || [];
                if (vulns.length > 0) {
                    out += `    <span style="color:#ffa500;">⚠ ${vulns.length} vulnerabilities detected</span>\n`;
                    vulns.slice(0, 8).forEach(v => {
                        out += `      <span style="color:#555;">└</span> ${escHtml(v)}\n`;
                    });
                    if (vulns.length > 8) {
                        out += `      <span style="color:#555;">  ... and ${vulns.length - 8} more</span>\n`;
                    }
                }
            });
        }
    }
    else {
        // Fallback for unknown tool types
        out += formatGeneric(d);
    }

    return out || '<span style="color:#888;">No data available.</span>';
}

function renderList(label, arr) {
    if (!arr || arr.length === 0) return '';
    let out = `<span style="color:var(--accent-color);">${label} (${arr.length})</span>\n`;
    arr.forEach(item => {
        out += `  <span style="color:#4caf50;">▸</span> ${escHtml(String(item))}\n`;
    });
    out += '\n';
    return out;
}

function formatGeneric(obj, indent = 0) {
    let out = '';
    const pad = '  '.repeat(indent);
    if (typeof obj !== 'object' || obj === null) {
        return pad + escHtml(String(obj)) + '\n';
    }
    if (Array.isArray(obj)) {
        obj.forEach(item => { out += formatGeneric(item, indent); });
        return out;
    }
    for (const [key, val] of Object.entries(obj)) {
        const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        if (Array.isArray(val)) {
            out += `${pad}<span style="color:var(--accent-color);">${label}:</span>\n`;
            val.forEach(item => {
                out += `${pad}  <span style="color:#4caf50;">▸</span> ${escHtml(String(item))}\n`;
            });
        } else if (typeof val === 'object' && val !== null) {
            out += `${pad}<span style="color:var(--accent-color);">${label}:</span>\n`;
            out += formatGeneric(val, indent + 1);
        } else {
            out += `${pad}<span style="color:#888;">${label}:</span> ${escHtml(String(val ?? 'N/A'))}\n`;
        }
    }
    return out;
}

function escHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
