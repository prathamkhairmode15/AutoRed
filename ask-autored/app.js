import { auth, onAuthStateChanged, signOut } from '../js/firebase.js';

const API_BASE_URL = window.API_BASE_URL;
const userDisplay = document.getElementById("user-display");
const logoutBtn = document.getElementById("logout-btn");
const themeToggle = document.getElementById("theme-toggle");

let currentUser = null;
let idToken = null;

onAuthStateChanged(auth, async (user) => {
  if (user) {
    currentUser = user;
    if(userDisplay) userDisplay.textContent = user.email.split('@')[0].toUpperCase();
    idToken = await user.getIdToken();
  } else {
    window.location.replace('../login/index.html');
  }
});

if(logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
        await signOut(auth);
        window.location.replace('../index.html');
    });
}

if(themeToggle) {
    themeToggle.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-theme");
        const newTheme = currentTheme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", newTheme);
        localStorage.setItem("theme", newTheme);
        themeToggle.textContent = `THEME: ${newTheme.toUpperCase()}`;
    });
    themeToggle.textContent = `THEME: ${(document.documentElement.getAttribute("data-theme") || "dark").toUpperCase()}`;
}

// Chat Logic
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const chatHistory = document.getElementById('chat-history');
const btnText = document.getElementById('btn-text');
const submitBtn = chatForm.querySelector('button');

function appendMessage(role, text) {
    const isBot = role === 'bot';
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${role}`;
    
    // Style alignments
    messageDiv.style.alignSelf = isBot ? 'flex-start' : 'flex-end';
    messageDiv.style.maxWidth = '80%';
    
    // Bubble Styling
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    bubble.style.padding = '1.5rem';
    bubble.style.borderRadius = 'var(--border-radius)';
    
    if(isBot) {
        bubble.style.background = 'var(--box-bg)';
        bubble.style.border = '1px solid var(--border-color)';
    } else {
        bubble.style.background = 'var(--accent-glow-soft)';
        bubble.style.border = '1px solid var(--accent-color)';
    }

    // Header
    const header = document.createElement('span');
    header.className = 'pixel-font';
    header.style.color = isBot ? 'var(--accent-color)' : 'var(--text-primary)';
    header.style.display = 'block';
    header.style.marginBottom = '0.5rem';
    header.style.fontSize = '0.9rem';
    header.textContent = isBot ? 'AutoRed' : 'You';
    
    // Content container
    const content = document.createElement('div');
    content.style.color = 'var(--text-primary)';
    content.style.lineHeight = '1.6';
    // Using white-space pre-wrap to preserve newlines
    content.style.whiteSpace = 'pre-wrap'; 
    content.textContent = text;
    
    bubble.appendChild(header);
    bubble.appendChild(content);
    messageDiv.appendChild(bubble);
    chatHistory.appendChild(messageDiv);
    
    // Scroll to bottom
    chatHistory.scrollTop = chatHistory.scrollHeight;
    
    return content;
}

chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const prompt = chatInput.value.trim();
    if(!prompt) return;
    
    // Append User Message
    appendMessage('user', prompt);
    chatInput.value = '';
    
    // Disable input while generating
    chatInput.disabled = true;
    submitBtn.disabled = true;
    btnText.textContent = '...';
    
    // Prepare Bot Message container
    const botTextNode = appendMessage('bot', '');
    
    try {
        if (!idToken && currentUser) {
            idToken = await currentUser.getIdToken(true);
        }
        
        const response = await fetch(`${API_BASE_URL}/chat`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${idToken}` 
            },
            body: JSON.stringify({ message: prompt })
        });
        
        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }
        
        // Streaming Logic
        const reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8");
        
        let done = false;
        let streamedText = "";
        
        while (!done) {
            const { value, done: readerDone } = await reader.read();
            done = readerDone;
            
            if (value) {
                const chunk = decoder.decode(value, { stream: true });
                streamedText += chunk;
                botTextNode.textContent = streamedText;
                
                // Keep scrolling down as text arrives
                chatHistory.scrollTop = chatHistory.scrollHeight;
            }
        }
        
    } catch (err) {
        botTextNode.textContent = `[Connection Error: ${err.message}]`;
        botTextNode.style.color = 'var(--accent-color)';
    } finally {
        chatInput.disabled = false;
        submitBtn.disabled = false;
        btnText.textContent = 'Send';
        chatInput.focus();
    }
});
