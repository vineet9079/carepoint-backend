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
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL
      );
    `);
    
    await db.query(`
      CREATE TABLE IF NOT EXISTS sync_data (
        id VARCHAR(100) PRIMARY KEY,
        collection VARCHAR(50) NOT NULL,
        payload JSONB NOT NULL,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS reset_requested BOOLEAN DEFAULT false,
      ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP;
    `);
    
    console.log("--> Database tables verified and patched.");

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
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' } 
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
// REAL WHATSAPP OTP DISPATCH ROUTE
// ==========================================
app.post('/api/auth/send-otp', async (req, res) => {
  const { phone, otp } = req.body;
  
  if (!phone || !otp) {
    return res.status(400).json({ success: false, error: 'Phone and OTP required.' });
  }

  try {
    // 1. Clean the phone number (removes any accidental spaces typed by the user)
    const cleanPhone = phone.replace(/\s+/g, '');

    // 2. Initialize Twilio
    const twilioClient = require('twilio')(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
    
    // 3. Dispatch using standard Twilio Sandbox formatting to bypass trial blocks
    await twilioClient.messages.create({
      body: `Your Twilio code is ${otp}`, 
      from: 'whatsapp:+17372508034', 
      to: `whatsapp:+91${cleanPhone}`
    });

    console.log(`[WHATSAPP OTP GATEWAY] OTP sent to: +91 ${cleanPhone}`);
    res.json({ success: true, message: 'OTP dispatched successfully via WhatsApp.' });
  } catch (error) {
    console.error('WhatsApp OTP dispatch error:', error);
    res.status(500).json({ success: false, error: 'Failed to send WhatsApp OTP.' });
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
    await db.query(
      'UPDATE users SET password = $1, password_changed_at = CURRENT_TIMESTAMP WHERE LOWER(username) = $2', 
      [hashedNewPassword, cleanUsername]
    );

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
// SECURITY MIDDLEWARE
// ==========================================
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Access denied. No token provided.', forceLogout: true });

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userResult = await db.query('SELECT password_changed_at FROM users WHERE id = $1', [decoded.id]);
    
    if (userResult.rowCount > 0 && userResult.rows[0].password_changed_at) {
      const passwordChangedTime = new Date(userResult.rows[0].password_changed_at).getTime() / 1000;
      if (decoded.iat < passwordChangedTime) {
        return res.status(401).json({ error: 'Password was changed. Session expired.', forceLogout: true });
      }
    }

    req.user = decoded; 
    next(); 
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.', forceLogout: true });
  }
};

// ==========================================
// UNIVERSAL CLOUD SYNC ROUTES (Protected)
// ==========================================
const validCollections = ['patients', 'appointments', 'prescriptions', 'inventory', 'lab-orders', 'lab-reports', 'invoices', 'notifications'];
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

app.post('/api/:collection', verifyToken, async (req, res, next) => {
  const { collection } = req.params;
  if (!validCollections.includes(collection)) return next();

  const payload = req.body;
  if (!payload || !payload.id) return res.status(400).json({ error: 'Missing payload or ID' });

  try {
    await db.query(`
      INSERT INTO sync_data (id, collection, payload, last_updated)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
      ON CONFLICT (id) 
      DO UPDATE SET payload = EXCLUDED.payload, last_updated = CURRENT_TIMESTAMP;
    `, [payload.id, collection, payload]);
    
    res.json({ success: true });
  } catch (err) {
    console.error(`Error pushing ${collection}:`, err);
    res.status(500).json({ success: false });
  }
});

app.put('/api/:collection/:id', verifyToken, async (req, res, next) => {
  const { collection, id } = req.params;
  if (!validCollections.includes(collection)) return next();

  const payload = req.body;
  try {
    await db.query(`
      INSERT INTO sync_data (id, collection, payload, last_updated)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
      ON CONFLICT (id) 
      DO UPDATE SET payload = EXCLUDED.payload, last_updated = CURRENT_TIMESTAMP;
    `, [id, collection, payload]);
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.delete('/api/:collection/:id', verifyToken, async (req, res, next) => {
  const { collection, id } = req.params;
  
  if (!validCollections.includes(collection)) return next();

  try {
    const result = await db.query(
      'DELETE FROM sync_data WHERE collection = $1 AND id = $2 RETURNING id', 
      [collection, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Record not found in cloud' });
    }
    
    res.json({ success: true, message: 'Record permanently deleted from cloud.' });
  } catch (err) {
    console.error(`Error deleting from ${collection}:`, err);
    res.status(500).json({ success: false, error: 'Database deletion failed' });
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
// WHATSAPP NOTIFICATION DISPATCH ROUTE
// ==========================================
app.post('/api/notify/whatsapp', verifyToken, async (req, res) => {
  const { phone, message } = req.body;
  
  if (!phone || !message) {
    return res.status(400).json({ success: false, error: 'Phone number and message are required.' });
  }

 try {
    // Live Twilio Integration
    const twilioClient = require('twilio')(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
    
    await twilioClient.messages.create({ 
      body: message, 
      from: 'whatsapp:+17372508034', // Your Twilio Sandbox number
      to: `whatsapp:+91${phone}` 
    });

    console.log(`[WHATSAPP LIVE GATEWAY] Message sent to: +91 ${phone}`);
    res.json({ success: true, message: 'WhatsApp notification dispatched successfully.' });
  } catch (error) {
    console.error('WhatsApp dispatch error:', error);
    res.status(500).json({ success: false, error: 'Failed to dispatch WhatsApp message.' });
  }
}); // <-- THIS CLOSING BRACKET WAS MISSING!

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`CarePoint Enterprise API listening on port ${PORT}`);
});