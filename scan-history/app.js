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
});

themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
    themeToggle.textContent = `THEME: ${newTheme.toUpperCase()}`;
});
themeToggle.textContent = `THEME: ${(document.documentElement.getAttribute("data-theme") || "dark").toUpperCase()}`;

async function fetchHistory() {
    try {
        const res = await fetch(`${API_BASE_URL}/scans`, {
            headers: { "Authorization": `Bearer ${idToken}` }
        });
        if (!res.ok) throw new Error("Failed to fetch history");

        const scans = await res.json();
        
        if (scans.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 2rem;">No history found.</td></tr>';
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

        // Attach listeners matching the data-id dynamically created
        document.querySelectorAll('.btn-primary[data-id]').forEach(btn => {
            btn.addEventListener('click', (e) => openModal(e.target.dataset.id, e.target.dataset.target));
        });

    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#ff3b3b;">${err.message}</td></tr>`;
    }
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
            html += `
                <div class="data-section">
                    <div class="data-title">[SOURCE] ${r.type.toUpperCase()}</div>
                    <div class="data-content">${JSON.stringify(r.parsed_data, null, 2)}</div>
                </div>
            `;
        });
        
        modalBody.innerHTML = html;
    } catch (err) {
        modalBody.innerHTML = `<p style="text-align:center; color: #ff3b3b;">Error: ${err.message}</p>`;
    }
}
