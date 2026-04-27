import { auth, onAuthStateChanged, signOut } from '../js/firebase.js';

const API_BASE_URL = "http://localhost:8000/api";
const userDisplay = document.getElementById("user-display");
const logoutBtn = document.getElementById("logout-btn");
const themeToggle = document.getElementById("theme-toggle");
const tableBody = document.getElementById("reports-table-body");

let currentUser = null;
let idToken = null;

onAuthStateChanged(auth, async (user) => {
  if (user) {
    currentUser = user;
    userDisplay.textContent = user.email.split('@')[0].toUpperCase();
    idToken = await user.getIdToken();
    fetchReports();
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

async function fetchReports() {
    try {
        const res = await fetch(`${API_BASE_URL}/scans`, {
            headers: { "Authorization": `Bearer ${idToken}` }
        });
        if (!res.ok) throw new Error("Failed to fetch reports");

        const scans = await res.json();
        const completedScans = scans.filter(s => s.status === 'completed');
        
        if (completedScans.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 2rem;">No completed scans available for report generation.</td></tr>';
            return;
        }

        tableBody.innerHTML = completedScans.map(scan => `
            <tr>
              <td>${scan.target}</td>
              <td style="color: var(--accent-color)">COMPLETED</td>
              <td>${scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</td>
              <td>
                <button class="download-btn" data-id="${scan.id}" data-target="${scan.target}">
                  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                  Generate PDF
                </button>
              </td>
            </tr>
        `).join('');

        document.querySelectorAll('.download-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const button = e.currentTarget;
                const scanId = button.dataset.id;
                const target = button.dataset.target;
                
                button.disabled = true;
                button.innerHTML = 'Processing...';
                
                await generatePDF(scanId, target);
                
                button.disabled = false;
                button.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Generate PDF`;
            });
        });

    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#ff3b3b;">${err.message}</td></tr>`;
    }
}

async function generatePDF(scanId, target) {
    try {
        const res = await fetch(`${API_BASE_URL}/scan/${scanId}`, {
            headers: { "Authorization": `Bearer ${idToken}` }
        });
        if (!res.ok) throw new Error("Failed to fetch scan details");
        const data = await res.json();
        
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        let yPos = 20;

        // Title styling
        doc.setFontSize(22);
        doc.setTextColor(255, 59, 59); // AutoRed Accent Color
        doc.text("AutoRed APT Intelligence", 105, yPos, { align: "center" });
        
        yPos += 15;
        doc.setFontSize(14);
        doc.setTextColor(50, 50, 50);
        doc.text(`Target: ${target}`, 20, yPos);
        
        yPos += 8;
        doc.setFontSize(10);
        doc.text(`Report Generated On: ${new Date().toLocaleString()}`, 20, yPos);
        doc.line(20, yPos + 5, 190, yPos + 5);

        yPos += 15;

        // Content
        const results = data.results || [];
        if (results.length === 0) {
            doc.text("No parsed intelligence data was found for this target.", 20, yPos);
        } else {
            results.forEach(r => {
                const parsed = r.parsed_data;
                if (!parsed) return;

                // Tool Header
                doc.setFontSize(12);
                doc.setTextColor(0, 0, 0);
                doc.setFont("helvetica", "bold");
                doc.text(`Module: ${r.type.toUpperCase()}`, 20, yPos);
                yPos += 8;

                // Parsing Logic
                doc.setFontSize(10);
                doc.setFont("helvetica", "normal");
                doc.setTextColor(80, 80, 80);

                const checkPageBreak = (spaceNeeded = 6) => {
                    if (yPos + spaceNeeded > 280) {
                        doc.addPage();
                        yPos = 20;
                    }
                };

                if (r.type === 'nslookup') {
                    const ips = parsed.ip_addresses || [];
                    doc.text(`Resolved IP Addresses:`, 25, yPos); yPos += 6; checkPageBreak();
                    ips.forEach(ip => { doc.text(`- ${ip}`, 30, yPos); yPos += 6; checkPageBreak(); });
                    
                    const aRec = parsed.a_records || [];
                    if (aRec.length > 0) {
                        doc.text(`A Records:`, 25, yPos); yPos += 6; checkPageBreak();
                        aRec.forEach(ip => { doc.text(`- ${ip}`, 30, yPos); yPos += 6; checkPageBreak(); });
                    }
                    
                    const aaaaRec = parsed.aaaa_records || [];
                    if (aaaaRec.length > 0) {
                        doc.text(`AAAA Records:`, 25, yPos); yPos += 6; checkPageBreak();
                        aaaaRec.forEach(ip => { doc.text(`- ${ip}`, 30, yPos); yPos += 6; checkPageBreak(); });
                    }
                    
                    const mxRec = parsed.mx_records || [];
                    if (mxRec.length > 0) {
                        doc.text(`Mail Servers (MX):`, 25, yPos); yPos += 6; checkPageBreak();
                        mxRec.forEach(rec => { doc.text(`- ${rec}`, 30, yPos); yPos += 6; checkPageBreak(); });
                    }
                    
                    const nsRec = parsed.ns_records || [];
                    if (nsRec.length > 0) {
                        doc.text(`Name Servers (NS):`, 25, yPos); yPos += 6; checkPageBreak();
                        nsRec.forEach(rec => { doc.text(`- ${rec}`, 30, yPos); yPos += 6; checkPageBreak(); });
                    }
                    
                    const txtRec = parsed.txt_records || [];
                    if (txtRec.length > 0) {
                        doc.text(`TXT Records:`, 25, yPos); yPos += 6; checkPageBreak();
                        txtRec.forEach(txt => { 
                             const splitTxt = doc.splitTextToSize(`- ${txt}`, 150);
                             checkPageBreak(splitTxt.length * 5);
                             doc.text(splitTxt, 30, yPos); 
                             yPos += 5 * splitTxt.length;
                             yPos += 2;
                        });
                    }
                } 
                else if (r.type === 'whois') {
                    const fields = [
                        { label: "Registrar", key: "registrar" },
                        { label: "Creation Date", key: "creation_date" },
                        { label: "Expiry Date", key: "expiry_date" },
                        { label: "Updated Date", key: "updated_date" },
                        { label: "Organization", key: "organization" },
                        { label: "Email", key: "email" },
                        { label: "Phone", key: "phone" },
                        { label: "Registrant Name", key: "registrant_name" }
                    ];
                    fields.forEach(f => {
                        doc.text(`${f.label}: ${parsed[f.key] || 'Unknown'}`, 25, yPos); yPos += 6; checkPageBreak();
                    });
                    
                    const nsRec = parsed.name_servers || [];
                    if (nsRec.length > 0) {
                        doc.text(`Name Servers:`, 25, yPos); yPos += 6; checkPageBreak();
                        nsRec.forEach(ns => { doc.text(`- ${ns}`, 30, yPos); yPos += 6; checkPageBreak(); });
                    }
                }
                else if (r.type === 'theHarvester') {
                    const emails = parsed.emails || [];
                    const subs = parsed.subdomains || [];
                    
                    doc.text(`Discovered Emails (${emails.length}):`, 25, yPos); yPos += 6; checkPageBreak();
                    emails.forEach(e => { doc.text(`- ${e}`, 30, yPos); yPos += 6; checkPageBreak(); });
                    yPos += 4; checkPageBreak();

                    doc.text(`Subdomains Discovered (${subs.length}):`, 25, yPos); yPos += 6; checkPageBreak();
                    subs.forEach(s => { doc.text(`- ${s}`, 30, yPos); yPos += 6; checkPageBreak(); });
                }
                else if (r.type === 'nmap') {
                    const ports = parsed.ports || [];
                    doc.text(`Open Ports & Services Found:`, 25, yPos); yPos += 6; checkPageBreak();
                    if (ports.length === 0) {
                        doc.text(`- No open ports discovered in fast scan.`, 30, yPos); yPos += 6; checkPageBreak();
                    } else {
                        ports.forEach(p => {
                            doc.text(`- ${p.port} (${p.service}): ${p.version}`, 30, yPos); yPos += 6; checkPageBreak();
                        });
                    }
                }

                yPos += 10;
                checkPageBreak();
            });
        }

        // Save PDF natively via user's browser
        doc.save(`AutoRed_Intelligence_${target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.pdf`);

    } catch (err) {
        alert("Report generation failed: " + err.message);
    }
}
