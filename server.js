require('dotenv').config();
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
    // 1. Ensure table exists
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL
      );
    `);
    
    // 2. PATCH: Force the database to add the missing column if it doesn't exist
    await db.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS reset_requested BOOLEAN DEFAULT false;
    `);
    
    console.log("--> Database tables verified and patched.");

    // 3. Verify Admin account
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
// LOGIN AUTHENTICATION ROUTE
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
      res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
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
        `UPDATE users SET username = $1, password = $2, role = $3 WHERE LOWER(username) = $4`,
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
    await db.query(`DELETE FROM users WHERE LOWER(username) = $1`, [usernameToDelete]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting staff:', error);
    res.status(500).json({ error: 'Server error while deleting staff' });
  }
});

// ==========================================
// CHANGE PASSWORD
// ==========================================
app.put('/api/staff/change-password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  const cleanUsername = username ? username.trim().toLowerCase() : '';

  try {
    const result = await db.query('SELECT * FROM users WHERE LOWER(username) = $1', [cleanUsername]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found.' });
    
    const user = result.rows[0];

    const isOldPasswordCorrect = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordCorrect) {
      return res.status(400).json({ error: 'Incorrect current password.' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password = $1 WHERE LOWER(username) = $2', [hashedNewPassword, cleanUsername]);

    res.json({ success: true });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Server error while changing password.' });
  }
});

// ==========================================
// FORGOT PASSWORD: REQUEST RESET
// ==========================================
app.post('/api/auth/request-reset', async (req, res) => {
  const { username } = req.body;
  const cleanUsername = username ? username.trim().toLowerCase() : '';

  try {
    const result = await db.query(
      "UPDATE users SET reset_requested = true WHERE LOWER(username) = $1 RETURNING id",
      [cleanUsername]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: "User not found." });
    }

    res.json({ success: true, message: "Reset request sent to admin." });
  } catch (err) {
    console.error("Reset request error:", err);
    res.status(500).json({ success: false, error: "Server error during password reset request." });
  }
});

// ==========================================
// ADMIN APPROVE & RESET PASSWORD
// ==========================================
app.post('/api/staff/admin-reset-password', async (req, res) => {
  const { username } = req.body;
  const cleanUsername = username ? username.trim().toLowerCase() : '';

  try {
    const tempPassword = `CarePoint${Math.floor(1000 + Math.random() * 9000)}`;
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    const result = await db.query(
      "UPDATE users SET password = $1, reset_requested = false WHERE LOWER(username) = $2 RETURNING id",
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
// AI CHATBOT ENDPOINT (GROQ GPT-OSS-20B)
// ==========================================
const groq = new OpenAI({
  apiKey: process.env.GROQ_API_KEY,
  baseURL: "https://api.groq.com/openai/v1",
});

app.post('/api/chat', async (req, res) => {
  try {
    const { message, context, userRole } = req.body;
    
    const systemPrompt = `You are a helpful, professional hospital AI assistant for the CarePoint Health Management System. 
    The current user is a ${userRole}. 
    Current Hospital Data: ${JSON.stringify(context)}.
    Answer the user concisely based on this data.`;

    const completion = await groq.chat.completions.create({
      model: "openai/gpt-oss-20b", 
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message }
      ],
    });

    res.json({ reply: completion.choices[0].message.content });
  } catch (error) {
    console.error('Groq API Error:', error);
    res.status(500).json({ error: 'My AI core is currently offline. Please check the backend connection.' });
  }
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`CarePoint Enterprise API listening on port ${PORT}`);
});