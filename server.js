/**
 * server.js - Main entry point for the Auth App
 * Vercel: exported app is used as serverless handler. Local: app.listen(port) starts the server.
 */

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const { pool, initDatabase } = require('./db');

const app = express();
const port = process.env.PORT || 3000;

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static frontend (register.html, login.html, style.css, script.js, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Root route: serve index.html (which redirects to register.html)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Ensure DB and users table exist (once per serverless cold start)
let dbReady = null;
function ensureDb() {
  if (!dbReady) dbReady = initDatabase();
  return dbReady;
}

// ============================================
// REGISTRATION
// ============================================
// Collects: user_id, name, email, phone, password
// Password is hashed with bcrypt before storing.
app.post('/api/register', async (req, res) => {
  const { user_id, name, email, phone, password } = req.body;

  if (!user_id || !name || !email || !phone || !password) {
    return res.status(400).json({ success: false, message: 'All fields are required.' });
  }

  try {
    await ensureDb();
    // Hash password so we never store plain text (bcrypt, 10 rounds)
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.execute(
      'INSERT INTO users (user_id, name, email, phone, password) VALUES (?, ?, ?, ?, ?)',
      [user_id.trim(), name.trim(), email.trim(), phone.trim(), hashedPassword]
    );

    res.json({ success: true, message: 'Registration successful. Redirecting to login...' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ success: false, message: 'User ID or Email already exists.' });
    }
    console.error('Registration error:', err);
    res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ============================================
// LOGIN
// ============================================
// HOW LOGIN WORKS:
// 1. User sends user_id OR email plus password.
// 2. We find the user by user_id or email in the database.
// 3. We compare the submitted password with the stored hash using bcrypt.compare.
// 4. If they match, login is successful; we return success and the client redirects to Netflix URL.
// 5. If not, we return an error message.
app.post('/api/login', async (req, res) => {
  const { loginId, password } = req.body;
  // loginId can be either user_id or email

  if (!loginId || !password) {
    return res.status(400).json({ success: false, message: 'User ID/Email and password are required.' });
  }

  try {
    await ensureDb();
    const [rows] = await pool.execute(
      'SELECT id, user_id, email, password FROM users WHERE user_id = ? OR email = ?',
      [loginId.trim(), loginId.trim()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid User ID/Email or password.' });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid User ID/Email or password.' });
    }

    res.json({ success: true, message: 'Login successful!' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// Start server when run locally (not on Vercel serverless)
if (process.env.VERCEL !== '1') {
  ensureDb()
    .then(() => {
      app.listen(port, () => {
        console.log('Server running on port', port);
      });
    })
    .catch((err) => {
      console.error('Database connection failed. Server not started.', err.message);
      process.exit(1);
    });
}

module.exports = app;
