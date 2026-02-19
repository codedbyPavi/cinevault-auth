/**
 * server.js - Main entry point for the Auth App
 *
 * When server starts:
 * 1. Connects to database
 * 2. Creates users table if not exists
 * 3. Serves static frontend and API routes
 */

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const { pool, initDatabase } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from 'public' folder (register.html, login.html, style.css, script.js)
app.use(express.static(path.join(__dirname, 'public')));

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

// ============================================
// START SERVER (waits for DB before listening)
// ============================================
async function start() {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log('Server running on http://localhost:' + PORT);
    });
  } catch (err) {
    console.error('Database connection failed. Server not started.');
    console.error('Error:', err.message);
    process.exit(1);
  }
}

start();
