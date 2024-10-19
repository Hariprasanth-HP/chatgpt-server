const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const express = require('express');
const router = express.Router();
let users = []; // In-memory users array (should be a database in a real app)
let refreshTokens = []; // Store refresh tokens temporarily
dotenv.config();

// Function to generate access tokens
const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
};

// Function to generate refresh tokens
const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '24h' });
    refreshTokens.push(refreshToken);
    return refreshToken;
};


router.get('/', (req, res) => {
    res.json('hi');

})

// Signup Route (Registers new user)
router.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    // Check if user already exists
    const userExists = users.find(user => user.email === email);
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save new user
    const newUser = { id: users.length + 1, email, password: hashedPassword };
    users.push(newUser);

    // Generate access and refresh tokens
    const accessToken = generateAccessToken({ id: newUser.id, email: newUser.email });
    const refreshToken = generateRefreshToken({ id: newUser.id, email: newUser.email });

    res.status(201).json({
        message: 'User registered successfully',
        accessToken,
        refreshToken,
    });
});

// Login Route (Authenticates user)
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Find user in database (memory in this case)
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: 'User not found' });

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(403).json({ message: 'Incorrect password' });

    // Generate access and refresh tokens
    const accessToken = generateAccessToken({ id: user.id, email: user.email });
    const refreshToken = generateRefreshToken({ id: user.id, email: user.email });

    res.json({
        userEmail: email,
        accessToken,
        refreshToken,
    });
});

// Token refresh route
router.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (!refreshToken) return res.sendStatus(401);

    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const newAccessToken = generateAccessToken({ id: user.id, email: user.email });
        res.json({ accessToken: newAccessToken, refreshToken, userEmail: user.email });
    });
});

// Logout route (Optional: Invalidate refresh tokens)
router.post('/logout', (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    res.sendStatus(204);
});

// Protected route example
router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is protected data', user: req.user });
});

// Middleware to authenticate access token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
module.exports = router;