// server.js

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const http = require('http'); // Node.js built-in HTTP module
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // <--- ADD THIS
const jwt = require('jsonwebtoken'); // <--- ADD THIS

const app = express();
const server = http.createServer(app); // Create an HTTP server instance from our Express app
const io = new socketIo.Server(server, {
    cors: {
        origin: "https://SB-Chat-App.onrender.com", // <--- IMPORTANT: REPLACE THIS
        methods: ["GET", "POST"],
        credentials: true
    }
}); // Attach Socket.IO to the HTTP server

// Middleware to parse JSON bodies (for future API routes if needed)
app.use(express.json());

// Serve static files from a 'public' directory
// We will create this 'public' directory in the next step for our frontend files.
app.use(express.static('public'));

// -----------------------------------------------------------
// MongoDB Connection
// -----------------------------------------------------------

// -----------------------------------------------------------
// MongoDB Connection (KEEP AS IS)
// -----------------------------------------------------------
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error('Error: MONGODB_URI is not defined in .env file.');
    console.error('Please create a .env file in the project root with MONGODB_URI="your_mongodb_connection_string"');
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// -----------------------------------------------------------
// NEW: User Schema and Model
// -----------------------------------------------------------
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    }
});

// Hash password before saving the user (pre-save hook)
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) { // Only hash if password field is modified (or new)
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

const User = mongoose.model('User', userSchema);

// -----------------------------------------------------------
// MODIFIED: Message Schema and Model
// -----------------------------------------------------------
const messageSchema = new mongoose.Schema({
    // Change 'username' to 'user' and make it a reference to the User model
    user: {
        type: mongoose.Schema.Types.ObjectId, // This is an ObjectId
        ref: 'User', // This tells Mongoose it refers to the 'User' model
        required: true
    },
    message: {
        type: String,
        required: true,
        trim: true
    },
    timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

// -----------------------------------------------------------
// JWT Secret (Add to .env)
// -----------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('Error: JWT_SECRET is not defined in .env file.');
    console.error('Please add JWT_SECRET="your_very_secret_key" to your .env file.');
    process.exit(1);
}

// -----------------------------------------------------------
// NEW: Auth Middleware
// -----------------------------------------------------------
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token'); // Typically sent in this header

    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user; // Attach user information from the token to the request
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// -----------------------------------------------------------
// NEW: Authentication Routes
// -----------------------------------------------------------

// @route   POST /api/register
// @desc    Register new user
// @access  Public
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    // Basic validation
    if (!username || !password) {
        return res.status(400).json({ msg: 'Please enter all fields' });
    }

    try {
        let user = await User.findOne({ username });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({
            username,
            password // The pre-save hook will hash this
        });

        await user.save();

        // Create JWT
        const payload = {
            user: {
                id: user.id,
                username: user.username // Include username in token for convenience
            }
        };

        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '1h' }, // Token expires in 1 hour
            (err, token) => {
                if (err) throw err;
                res.json({ token, username: user.username }); // Send token and username back
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/login
// @desc    Authenticate user & get token
// @access  Public
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // Basic validation
    if (!username || !password) {
        return res.status(400).json({ msg: 'Please enter all fields' });
    }

    try {
        let user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        // Create JWT
        const payload = {
            user: {
                id: user.id,
                username: user.username
            }
        };

        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, username: user.username });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/me
// @desc    Get logged in user info
// @access  Private (uses authMiddleware)
app.get('/api/me', authMiddleware, async (req, res) => {
    try {
        // req.user is set by authMiddleware from the JWT payload
        // Select everything except the password
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// -----------------------------------------------------------
// Socket.IO Connection (MODIFIED to use authenticated user)
// -----------------------------------------------------------

// Middleware for Socket.IO to authenticate connections
io.use(async (socket, next) => {
    // Get token from handshake query or headers (common for WebSocket auth)
    // For simplicity, we'll assume it's passed as a query param `token`
    const token = socket.handshake.query.token || socket.handshake.auth.token;

    if (!token) {
        return next(new Error('Authentication error: No token provided.'));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Attach the user object to the socket for later use
        socket.user = decoded.user;
        next();
    } catch (err) {
        return next(new Error('Authentication error: Invalid token.'));
    }
});


io.on('connection', async (socket) => {
    console.log(`User ${socket.user.username} connected with ID: ${socket.id}`);

    // When a new user connects, send them the last 100 messages
    // Populate the 'user' field to get username instead of just ID
    try {
        const messages = await Message.find().sort({ timestamp: 1 }).limit(100).populate('user', 'username');
        socket.emit('history', messages);
    } catch (err) {
        console.error('Error fetching message history:', err);
    }

    // Listen for 'chat message' events from clients
    socket.on('chat message', async (data) => {
        // The user ID is now available on socket.user.id
        const userId = socket.user.id;
        const messageText = data.message; // Client only sends the message text

        if (!messageText || messageText.trim() === '') {
            return; // Don't save empty messages
        }

        try {
            const newMessage = new Message({
                user: userId, // Store the ObjectId of the user
                message: messageText
            });

            await newMessage.save();

            // Populate the user field to send back the username to all clients
            // This ensures everyone sees the username, not just the ID
            await newMessage.populate('user', 'username');

            // Emit the message to ALL connected clients
            io.emit('chat message', newMessage);
        } catch (err) {
            console.error('Error saving message to DB or emitting:', err);
        }
    });

    // Listen for disconnection events
    socket.on('disconnect', () => {
        console.log(`User ${socket.user ? socket.user.username : 'Unknown'} disconnected: ${socket.id}`);
    });
});

// -----------------------------------------------------------
// Server Listen
// -----------------------------------------------------------

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Open your browser at http://localhost:${PORT}`);
});