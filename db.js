/**
 * db.js - Database connection and table setup for Aiven MySQL
 *
 * CREDENTIALS: Set DB_PASSWORD environment variable before running, e.g.:
 *   set DB_PASSWORD=your_password
 * Or paste your password below in DB_PASSWORD (avoid committing real passwords).
 */

const mysql = require('mysql2/promise');

// ============================================
// AIVEN MYSQL CREDENTIALS
// ============================================
const DB_HOST = process.env.DB_HOST || 'mysql-451a4f3-cambridge-f76d.b.aivencloud.com';
const DB_PORT = parseInt(process.env.DB_PORT || '27381', 10);
const DB_USER = process.env.DB_USER || 'avnadmin';
const DB_NAME = process.env.DB_NAME || 'defaultdb';
// Set DB_PASSWORD env var, or paste your Aiven password here (no quotes):
// IMPORTANT: Never commit real passwords to Git. Use environment variables.
const PASSWORD_FALLBACK = '';
const DB_PASSWORD = process.env.DB_PASSWORD || PASSWORD_FALLBACK;

if (!DB_PASSWORD) {
  console.error('DB_PASSWORD is missing. Set environment variable: set DB_PASSWORD=your_password');
  console.error('Or paste your Aiven password in db.js as PASSWORD_FALLBACK.');
  throw new Error('DB_PASSWORD required');
}

/**
 * Connection pool with SSL for Aiven MySQL.
 * rejectUnauthorized: false is required for Aiven's cloud certificates.
 */
const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false,
  },
});

/**
 * Users table schema - created automatically if it does not exist.
 */
const CREATE_USERS_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`;

/**
 * Initializes DB: verifies connection, then creates users table if missing.
 * Logs "Connected to MySQL" and "Table ready".
 */
async function initDatabase() {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('Connected to MySQL');
    await connection.query(CREATE_USERS_TABLE_SQL);
    console.log('Table ready');
  } catch (err) {
    console.error('Database initialization failed:', err.message);
    throw err;
  } finally {
    if (connection) connection.release();
  }
}

module.exports = { pool, initDatabase };
