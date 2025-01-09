const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

app.use(bodyParser.json());

// Simulated database (replace with real DB in production)
const users = [];

// Secret key for JWT
const SECRET_KEY = 'your_secret_key';

// Endpoint: User Registration
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    // Check if user already exists
    if (users.some(user => user.username === username)) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user in the database
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: 'User registered successfully' });
});

// Endpoint: User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Find user
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
});

// Endpoint: Protected Route
app.get('/dashboard', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }

    try {
        const user = jwt.verify(token, SECRET_KEY);
        res.json({ message: `Welcome to your dashboard, ${user.username}!` });
    } catch {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
