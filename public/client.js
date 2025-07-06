// public/client.js

let socket; // Declare socket globally so it can be initialized after auth
let currentUser = null; // To store the username of the logged-in user

// Get references to DOM elements
const chatApp = document.getElementById('chat-app');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('messageInput');
const chatContainer = document.getElementById('chat-container');
const authModal = new bootstrap.Modal(document.getElementById('authModal'));
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const authMessage = document.getElementById('authMessage');
const loggedInUserSpan = document.getElementById('loggedInUser');
const loginRegisterBtn = document.getElementById('loginRegisterBtn');
const logoutBtn = document.getElementById('logoutBtn');

// --- Helper Functions ---

function displayAuthMessage(message, type = 'danger') {
    authMessage.textContent = message;
    authMessage.className = `alert alert-${type}`;
    authMessage.classList.remove('d-none');
}

function clearAuthMessage() {
    authMessage.classList.add('d-none');
}

function displayMessage(username, message, timestamp) {
    const messageBubble = document.createElement('div');
    messageBubble.classList.add('message-bubble');

    const formattedTime = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    messageBubble.innerHTML = `
        <strong>${username}</strong> <span class="text-muted" style="font-size: 0.8em;">(${formattedTime})</span><br>
        ${message}
    `;
    chatContainer.appendChild(messageBubble);

    // Scroll to the bottom of the chat container
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

function showChatUI(username) {
    chatApp.style.display = 'flex'; // Show the chat elements
    loggedInUserSpan.textContent = `Logged in as: ${username}`;
    loggedInUserSpan.classList.remove('d-none');
    loginRegisterBtn.classList.add('d-none');
    logoutBtn.classList.remove('d-none');
    authModal.hide(); // Hide the modal if it's open
    clearAuthMessage();
}

function hideChatUI() {
    chatApp.style.display = 'none'; // Hide the chat elements
    loggedInUserSpan.textContent = '';
    loggedInUserSpan.classList.add('d-none');
    loginRegisterBtn.classList.remove('d-none');
    logoutBtn.classList.add('d-none');
    chatContainer.innerHTML = ''; // Clear chat messages on logout
    currentUser = null;
    if (socket) {
        socket.disconnect(); // Disconnect existing socket connection
        socket = null;
    }
}

function initSocketConnection(token) {
    if (socket) { // Disconnect existing socket if any (e.g., re-login)
        socket.disconnect();
    }

    // Initialize Socket.IO connection, passing the JWT token
    socket = io({
        auth: {
            token: token
        }
    });

    socket.on('connect', () => {
        console.log('Connected to chat server!');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from chat server.');
    });

    socket.on('connect_error', (err) => {
        console.error('Socket.IO connection error:', err.message);
        // If it's an authentication error, prompt for re-login
        if (err.message.includes('Authentication error')) {
            alert('Your session has expired or is invalid. Please log in again.');
            localStorage.removeItem('token');
            localStorage.removeItem('username');
            hideChatUI();
            authModal.show();
        }
    });

    // Listen for 'chat message' events from the server
    socket.on('chat message', (msg) => {
        // msg.user will be an object with { _id, username } thanks to populate
        displayMessage(msg.user.username, msg.message, msg.timestamp);
    });

    // Listen for 'history' event from the server (when connecting)
    socket.on('history', (messages) => {
        messages.forEach(msg => {
            // msg.user will be an object with { _id, username } thanks to populate
            displayMessage(msg.user.username, msg.message, msg.timestamp);
        });
    });
}

// --- Authentication Logic ---

async function registerUser(username, password) {
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (response.ok) {
            displayAuthMessage('Registration successful! Please log in.', 'success');
            // Optionally auto-fill login form or close modal
            document.getElementById('loginUsername').value = username;
            document.getElementById('loginPassword').value = password;
        } else {
            displayAuthMessage(data.msg || 'Registration failed.');
        }
    } catch (error) {
        console.error('Registration error:', error);
        displayAuthMessage('An error occurred during registration.');
    }
}

async function loginUser(username, password) {
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token); // Store the JWT
            localStorage.setItem('username', data.username); // Store the username for display
            currentUser = data.username;
            initSocketConnection(data.token); // Initialize Socket.IO with the token
            showChatUI(currentUser);
        } else {
            displayAuthMessage(data.msg || 'Login failed.');
        }
    } catch (error) {
        console.error('Login error:', error);
        displayAuthMessage('An error occurred during login.');
    }
}

function logoutUser() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    hideChatUI();
    // Re-show the login/register modal
    authModal.show();
}

// --- Event Listeners ---

loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    clearAuthMessage();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    loginUser(username, password);
});

registerForm.addEventListener('submit', (e) => {
    e.preventDefault();
    clearAuthMessage();
    const username = document.getElementById('registerUsername').value.trim();
    const password = document.getElementById('registerPassword').value.trim();
    registerUser(username, password);
});

messageForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const message = messageInput.value.trim();
    if (message && socket && socket.connected) {
        socket.emit('chat message', { message: message }); // Only send message content, username is from auth
        messageInput.value = ''; // Clear the input field
    } else if (!socket || !socket.connected) {
        alert('Not connected to chat server. Please log in first.');
    }
});

logoutBtn.addEventListener('click', logoutUser);

// --- Initial Load Check ---
// Check for existing token on page load
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    const storedUsername = localStorage.getItem('username');

    if (token && storedUsername) {
        // Attempt to re-authenticate the socket connection
        currentUser = storedUsername;
        initSocketConnection(token);
        showChatUI(currentUser);
        // Optionally, verify token validity with a backend call (e.g., /api/me)
        // If the token is expired/invalid, the socket 'connect_error' will catch it.
    } else {
        // No token found, show login/register modal
        authModal.show();
    }
});