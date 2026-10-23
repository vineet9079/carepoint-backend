require('dotenv').config();
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'carepoint_super_secret_key_2026';
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Database Connection (Neon DB)
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==========================================
// SEED DATABASE (Safely Initialize Admin & Patch Schema)
// ==========================================
const seedDatabase = async () => {
  try {
    // 1. Ensure users table exists
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL
      );
    `);
    
    // 2. CREATE UNIVERSAL SYNC TABLE FOR HYBRID CLOUD APP
    await db.query(`
      CREATE TABLE IF NOT EXISTS sync_data (
        id VARCHAR(100) PRIMARY KEY,
        collection VARCHAR(50) NOT NULL,
        payload JSONB NOT NULL,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 3. PATCH: Force the database to add missing columns if they don't exist
    await db.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS reset_requested BOOLEAN DEFAULT false,
      ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP;
    `);
    
    console.log("--> Database tables verified and patched.");

    // 4. Verify Admin account
    const adminCheck = await db.query("SELECT * FROM users WHERE LOWER(username) = 'admin'");
    
    if (adminCheck.rowCount === 0) {
      const hashedAdminPass = await bcrypt.hash('admin', 10);
      await db.query(
        `INSERT INTO users (username, password, role) VALUES ($1, $2, $3)`,
        ['admin', hashedAdminPass, 'ADMIN']
      );
      console.log("--> Auto-seed: Admin account created successfully.");
    } else {
      console.log("--> Auto-seed: Admin account already exists. Password untouched.");
    }
  } catch (err) {
    console.error("Database seeding error:", err);
  }
};

// Run seed script on server start
seedDatabase();

// ==========================================
// LOGIN AUTHENTICATION ROUTE (Updated with JWT)
// ==========================================
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const cleanUsername = username ? username.trim().toLowerCase() : '';
  console.log(`--> Login attempt received for username: ${cleanUsername}`);

  try {
    const result = await db.query('SELECT * FROM users WHERE LOWER(username) = $1', [cleanUsername]);

    if (result.rowCount === 0) {
      return res.status(401).json({ success: false, error: 'Invalid username or password.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      console.log(`--> SUCCESS: Logging in user: ${user.username}`);
      
      // STEP 3: Generate a secure JWT token when user logs in
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' } // Token expires in 7 days
      );

      res.json({ 
        success: true, 
        token: token, 
        user: { id: user.id, username: user.username, role: user.role } 
      });
    } else {
      res.status(401).json({ success: false, error: 'Invalid username or password.' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// ==========================================
// GET ALL USERS / STAFF
// ==========================================
app.get('/api/staff', async (req, res) => {
  try {
    const result = await db.query('SELECT id, username, role, reset_requested FROM users ORDER BY id ASC');
    res.json({ success: true, staff: result.rows });
  } catch (error) {
    console.error('Error fetching staff:', error);
    res.status(500).json({ error: 'Server error while fetching staff' });
  }
});

// ==========================================
// ADD NEW STAFF ENDPOINT
// ==========================================
app.post('/api/staff/add', async (req, res) => {
  const { username, password, role } = req.body;
  const cleanUsername = username ? username.trim().toLowerCase() : '';
  
  try {
    const existingUser = await db.query('SELECT * FROM users WHERE LOWER(username) = $1', [cleanUsername]);
    if (existingUser.rowCount > 0) {
      return res.status(400).json({ success: false, error: 'Username already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO users (username, password, role) VALUES ($1, $2, $3)`,
      [cleanUsername, hashedPassword, role]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error creating staff:', error);
    res.status(500).json({ error: 'Server error while creating staff' });
  }
});

// ==========================================
// UPDATE STAFF / ADMIN ENDPOINT
// ==========================================
app.put('/api/staff/update', async (req, res) => {
  const { currentUsername, newUsername, password, role } = req.body;
  const cleanCurrent = currentUsername ? currentUsername.trim().toLowerCase() : '';
  const cleanNew = newUsername ? newUsername.trim().toLowerCase() : '';

  try {
    if (password && password.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.query(
        `UPDATE users SET username = $1, password = $2, role = $3, password_changed_at = CURRENT_TIMESTAMP WHERE LOWER(username) = $4`,
        [cleanNew, hashedPassword, role, cleanCurrent]
      );
    } else {
      await db.query(
        `UPDATE users SET username = $1, role = $2 WHERE LOWER(username) = $3`,
        [cleanNew, role, cleanCurrent]
      );
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating staff:', error);
    res.status(500).json({ error: 'Server error while updating staff' });
  }
});

// ==========================================
// DELETE STAFF ENDPOINT
// ==========================================
app.delete('/api/staff/:username', async (req, res) => {
  const usernameToDelete = req.params.username.trim().toLowerCase();

  try {
    await db.query(`DELETE FROM users WHERE LOWER(username) = $1`, [usernameToDelete]); res.json({ success: true }); } catch (error) { console.error('Error deleting staff:', error); res.status(500).json({ error: 'Server error while deleting staff' }); } });  // ========================================== // CHANGE PASSWORD // ========================================== app.put('/api/staff/change-password', async (req, res) => { const { username, oldPassword, newPassword } = req.body; const cleanUsername = username ? username.trim().toLowerCase() : '';  try { const result = await db.query('SELECT * FROM users WHERE LOWER(username) = $1', [cleanUsername]); if (result.rowCount === 0) return res.status(404).json({ error: 'User not found.' });  const user = result.rows[0];  const isOldPasswordCorrect = await bcrypt.compare(oldPassword, user.password); if (!isOldPasswordCorrect) { return res.status(400).json({ error: 'Incorrect current password.' }); }  const hashedNewPassword = await bcrypt.hash(newPassword, 10);  // STEP 2: Updates the password and logs the timestamp simultaneously await db.query( 'UPDATE users SET password = $1, password_changed_at = CURRENT_TIMESTAMP WHERE LOWER(username) = $2', [hashedNewPassword, cleanUsername] );  res.json({ success: true }); } catch (error) { console.error('Password change error:', error); res.status(500).json({ error: 'Server error while changing password.' }); } });  // ========================================== // FORGOT PASSWORD: REQUEST RESET // ========================================== app.post('/api/auth/request-reset', async (req, res) => { const { username } = req.body; const cleanUsername = username ? username.trim().toLowerCase() : '';  try { const result = await db.query( "UPDATE users SET reset_requested = true WHERE LOWER(username) = $1 RETURNING id", [cleanUsername] );  if (result.rowCount === 0) { return res.status(404).json({ success: false, error: "User not found." }); }  res.json({ success: true, message: "Reset request sent to admin." }); } catch (err) { console.error("Reset request error:", err); res.status(500).json({ success: false, error: "Server error during password reset request." }); } });  // ========================================== // ADMIN APPROVE & RESET PASSWORD // ========================================== app.post('/api/staff/admin-reset-password', async (req, res) => { const { username } = req.body; const cleanUsername = username ? username.trim().toLowerCase() : '';  try { const tempPassword = `CarePoint${Math.floor(1000 + Math.random() * 9000)}`;
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    // Logs the timestamp when admin resets the password
    const result = await db.query(
      "UPDATE users SET password = $1, reset_requested = false, password_changed_at = CURRENT_TIMESTAMP WHERE LOWER(username) = $2 RETURNING id",
      [hashedPassword, cleanUsername]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: "User not found." });
    }

    res.json({ 
      success: true, 
      tempPassword: tempPassword,
      message: `Password reset successfully for ${cleanUsername}` 
    });
  } catch (err) {
    console.error("Admin reset error:", err);
    res.status(500).json({ error: "Database error during admin password reset." });
  }
});

// ==========================================
// SECURITY MIDDLEWARE: VERIFY TOKEN & PASSWORD CHANGES
// ==========================================
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Access denied. No token provided.', forceLogout: true });

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if the user changed their password AFTER this token was issued
    const userResult = await db.query('SELECT password_changed_at FROM users WHERE id = $1', [decoded.id]);
    
    if (userResult.rowCount > 0 && userResult.rows[0].password_changed_at) {
      const passwordChangedTime = new Date(userResult.rows[0].password_changed_at).getTime() / 1000;
      
      // decoded.iat is the "Issued At" time of the token
      if (decoded.iat < passwordChangedTime) {
        return res.status(401).json({ error: 'Password was changed. Session expired.', forceLogout: true });
      }
    }

    req.user = decoded; // Attach user info to the request
    next(); // All good, proceed to the route!
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.', forceLogout: true });
  }
};

// ==========================================
// UNIVERSAL CLOUD SYNC ROUTES (Protected)
// ==========================================
const validCollections = ['patients', 'appointments', 'prescriptions', 'inventory', 'lab-orders', 'lab-reports', 'invoices'];

// 1. PULL: Send all cloud data to the local Electron app on startup
app.get('/api/:collection', verifyToken, async (req, res, next) => {
  const { collection } = req.params;
  if (!validCollections.includes(collection)) return next();

  try {
    const result = await db.query('SELECT payload FROM sync_data WHERE collection = $1', [collection]);
    const data = result.rows.map(row => row.payload);
    res.json({ success: true, data });
  } catch (err) {
    console.error(`Error pulling ${collection}:`, err);
    res.status(500).json({ success: false, error: 'Database fetch failed' });
  }
});

// 2. PUSH (New): Insert a new record into the cloud
app.post('/api/:collection', verifyToken, async (req, res, next) => {
  const { collection } = req.params;
  if (!validCollections.includes(collection)) return next();

  const payload = req.body;
  if (!payload || !payload.id) return res.status(400).json({ error: 'Missing payload or ID' });

  try {
    await db.query(`
      INSERT INTO sync