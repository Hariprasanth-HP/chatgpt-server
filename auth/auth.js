const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const express = require('express');
const pool = require('../pguserpool');
const router = express.Router();
const axios = require('axios');

let users = []; // In-memory users array (should be a database in a real app)
let refreshTokens = []; // Store refresh tokens temporarily
dotenv.config();

// Function to generate access tokens
const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
};

// Function to generate refresh tokens
const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '5m' });
    refreshTokens.push(refreshToken);
    return refreshToken;
};


router.get('/', (req, res) => {
    res.json('hi');

})

// Signup Route (Registers new user)
router.post('/signup', async (req, res) => {
    const { email, password} = req.body;

    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (userCheck.rows.length > 0) {
            // User already exists, return error
            return res.status(409).json({ message: 'User already exists with this email' });
        }
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
        'INSERT INTO users ( email, password) VALUES ($1, $2) RETURNING id',
        [ email, hashedPassword]
    );

    const userId = result.rows[0].id;

    const accessToken = generateAccessToken({ id: userId });
    const refreshToken = generateRefreshToken({ id: userId });

    res.status(201).json({
        message: 'User registered successfully',
        userEmail: email,
        accessToken,
        refreshToken,
    });
});

// Login Route (Authenticates user)
router.post('/login', async (req, res) => {


    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (user && await bcrypt.compare(password, user.password)) {
            // Generate tokens
            const accessToken = generateAccessToken({ id: user.id });
            const refreshToken = generateRefreshToken({ id: user.id });

            // Update the refresh token in the database
            await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

            res.json({
                message: 'User logged in successfully',
                userEmail: email,
                accessToken,
                refreshToken,
            });
        }
        else{
            res.status(401).json({ message: 'user does not exist' });
        }
    }
    catch (error) {
        console.error('Error logging in:', error);
        res.status(401).json({ error: 'Invalid credentials' });
    }

});

// Token refresh route
router.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (!refreshToken) return res.sendStatus(401);

    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) res.status(403).json({ message: 'Invalid or expired token' });
        const newAccessToken = generateAccessToken({ id: user.id, email: user.email });
        res.json({ accessToken: newAccessToken, refreshToken, userEmail: user.email,message:'token generated' });
    });
});
// Logout route
router.post('/logout', async (req, res) => {
    logoutUser(req,res)
});
const logoutUser = async(req, res)=>{
    const refreshToken = req.body.token;
    if (!refreshToken) return res.sendStatus(400); // Bad Request if no token provided

    try {
        // Remove the refresh token from the database
        const result = await pool.query('UPDATE users SET refresh_token = NULL WHERE refresh_token = $1', [refreshToken]);

        if (result.rowCount === 0) {
            return res.sendStatus(404); // Not Found if the token wasn't found
        }

        res.sendStatus(204); // No Content, successfully logged out
    } catch (error) {
        console.error('Error during logout:', error);
        res.sendStatus(500); // Internal Server Error
    }
}


// Protected route example
router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is protected data', user: req.user });
});

router.post('/api/generate', authenticateToken,async (req, res) => {
    console.log('req.body',req.body);
    
    try {
      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${process.env.GEMEINI_API_KEY}`,
        req.body
      );
      res.json(response.data);
    } catch (error) {
      console.error(error);
      res.status(500).send('Error generating content');
    }
  });

// Middleware to authenticate access token
 function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        console.error('JWT Error:', user); // Log the error for debugging
        if(err) res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}
module.exports = router;