const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Secret key for signing JWTs (MUST be kept secure in a real app)
const JWT_SECRET = 'your_super_secret_key_12345';
const TOKEN_EXPIRY = '1h';

// Mock User Database (only one user for simplicity)
const mockUser = {
    id: 101,
    username: 'user1',
    password: 'password123', // In a real app, this would be a hashed password
    balance: 1000.00
};

// --- Middleware for JWT Verification ---
const authenticateToken = (req, res, next) => {
    // Get the token from the Authorization header (Auth: Bearer TOKEN)
    const authHeader = req.headers['auth'];
    
    if (!authHeader) {
        return res.status(401).json({ message: 'Token required' });
    }

    // Attempt to verify the token
    jwt.verify(authHeader, JWT_SECRET, (err, user) => {
        if (err) {
            // 403 Forbidden for invalid or expired token, matching the screenshot
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// --- API Endpoints ---

/**
 * Public Endpoint: User Login (Generates JWT)
 * POST /login
 */
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username !== mockUser.username || password !== mockUser.password) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create payload for JWT (do NOT include the password)
    const token = jwt.sign({ id: mockUser.id, username: mockUser.username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

    res.status(200).json({
        message: 'Login successful',
        token: token
    });
});

/**
 * Protected Endpoint: Get Balance
 * GET /balance
 */
app.get('/balance', authenticateToken, (req, res) => {
    // Since the token is valid, we return the balance associated with the authenticated user
    res.status(200).json({
        balance: mockUser.balance
    });
});

/**
 * Protected Endpoint: Deposit Funds
 * POST /deposit
 */
app.post('/deposit', authenticateToken, (req, res) => {
    const { amount } = req.body;
    const depositAmount = Number(amount);

    if (isNaN(depositAmount) || depositAmount <= 0) {
        return res.status(400).json({ message: 'Invalid deposit amount' });
    }

    // Update balance
    mockUser.balance += depositAmount;

    res.status(200).json({
        message: `Deposited $${depositAmount}.`,
        newBalance: mockUser.balance
    });
});

/**
 * Protected Endpoint: Withdraw Funds
 * POST /withdraw
 */
app.post('/withdraw', authenticateToken, (req, res) => {
    const { amount } = req.body;
    const withdrawAmount = Number(amount);

    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ message: 'Invalid withdraw amount' });
    }

    if (mockUser.balance < withdrawAmount) {
        return res.status(400).json({ message: 'Insufficient funds for withdrawal.' });
    }

    // Update balance
    mockUser.balance -= withdrawAmount;

    res.status(200).json({
        message: `Withdrew $${withdrawAmount}.`,
        newBalance: mockUser.balance
    });
});

app.listen(port, () => {
    console.log(`Secure Banking API running on http://localhost:${port}`);
});
