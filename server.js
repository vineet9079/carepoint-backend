require('dotenv').config();
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'carepoint_super_secret_key_2026';
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');

const app = express();
app.use(cors());
app.use(express.json());

// Database Connection (Neon DB)
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==========================================
// LOGIN AUTHENTICATION ROUTE
// ==========================================
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const cleanUsername = username ? username.trim().toLowerCase() : '';

  try {
    const result = await db.query('SELECT * FROM staff WHERE LOWER(username) = $1', [cleanUsername]);

    if (result.rowCount === 0) {
      return res.status(401).json({ success: false, error: 'Invalid username or password.' });
    }

    const user = result.rows[0];
    
    let isMatch = false;
    if (user.password === 'admin' && password === 'admin') {
      isMatch = true;
      const hashedAdminPass = await bcrypt.hash('admin', 10);
      await db.query('UPDATE staff SET password = $1 WHERE username = $2', [hashedAdminPass, user.username]);
    } else {
      isMatch = await bcrypt.compare(password, user.password);
    }

    if (isMatch) {
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' } 
      );
      res.json({ success: true, token, user: { id: user.id, username: user.username, role: user.role } });
    } else {
      res.status(401).json({ success: false, error: 'Invalid username or password.' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// ==========================================
// REAL EMAIL OTP DISPATCH ROUTE
// ==========================================
app.post('/api/auth/send-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ success: false, error: 'Email and OTP required.' });

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        refresh_token: process.env.REFRESH_TOKEN,
        grant_type: 'refresh_token'
      })
    });

    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) throw new Error('Failed to get access token');

    const emailContent = [
      `To: ${email}`,
      `From: "CarePoint HMS" <${process.env.EMAIL_USER}>`,
      `Subject: CarePoint HMS - Secure Login OTP`,
      `Content-Type: text/html; charset=utf-8`,
      '',
      `<div style="text-align: center; font-family: Arial; padding: 20px;">`,
      `  <h2 style="color: #4355B9;">CarePoint HMS</h2>`,
      `  <p>Your secure login OTP is:</p>`,
      `  <h1 style="letter-spacing: 5px;">${otp}</h1>`,
      `</div>`
    ].join('\r\n');

    const base64EncodedEmail = Buffer.from(emailContent)
      .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const sendResponse = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: base64EncodedEmail })
    });

    if (!sendResponse.ok) throw new Error(await sendResponse.text());
    res.json({ success: true, message: 'OTP dispatched securely via Gmail HTTPS API.' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to send OTP.' });
  }
});

// ==========================================
// SECURE EMAIL NOTIFICATIONS (HTTPS BYPASS)
// ==========================================
app.post('/api/notify/email', async (req, res) => {
  const { email, subject, htmlMessage } = req.body;
  if (!email || !htmlMessage) return res.status(400).json({ error: 'Email and message required.' });

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        refresh_token: process.env.REFRESH_TOKEN,
        grant_type: 'refresh_token'
      })
    });
    const tokenData = await tokenResponse.json();
    
    const emailContent = [`To: ${email}`, `From: "CarePoint HMS" <${process.env.EMAIL_USER}>`, `Subject: ${subject}`, `Content-Type: text/html; charset=utf-8`, '', htmlMessage].join('\r\n');
    const base64EncodedEmail = Buffer.from(emailContent).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: base64EncodedEmail })
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send notification.' });
  }
});

// ==========================================
// GENERATE SECURE PATIENT TOKEN
// ==========================================
app.post('/api/auth/patient-token', async (req, res) => {
  const { email } = req.body;
  try {
    const token = jwt.sign({ id: email, role: 'patient' }, JWT_SECRET, { expiresIn: '7d' });
    const result = await db.query('SELECT * FROM patients WHERE email = $1 OR phone = $1', [email]);
    const patient = result.rows.length > 0 ? result.rows[0] : null;
    res.json({ success: true, token, patient });
  } catch (err) {
    res.status(500).json({ error: 'Server error generating token' });
  }
});

// ==========================================
// STAFF MANAGEMENT API
// ==========================================
app.get('/api/staff', async (req, res) => {
  try {
    const result = await db.query('SELECT id, name, username, role, badge_color, dot_color, inits FROM staff ORDER BY id ASC');
    res.json(result.rows); // Returns a clean array directly
  } catch (error) {
    res.status(500).json([]);
  }
});

app.post('/api/staff/add', async (req, res) => {
  const { id, name, username, password, role, badge_color, dot_color, inits } = req.body;
  const cleanUsername = username ? username.trim().toLowerCase() : '';
  try {
    const existing = await db.query('SELECT * FROM staff WHERE LOWER(username) = $1', [cleanUsername]);
    if (existing.rowCount > 0) return res.status(400).json({ success: false, error: 'Username already exists.' });

    const hashed = await bcrypt.hash(password, 10);
    const query = `INSERT INTO staff (id, name, username, password, role, badge_color, dot_color, inits) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`;
    const result = await db.query(query, [id, name, cleanUsername, hashed, role, badge_color, dot_color, inits]);
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/staff/update', async (req, res) => {
  const { currentUsername, newUsername, password, role } = req.body;
  const cleanCurrent = currentUsername ? currentUsername.trim().toLowerCase() : '';
  const cleanNew = newUsername ? newUsername.trim().toLowerCase() : '';

  try {
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await db.query(`UPDATE staff SET username = $1, password = $2, role = $3, password_changed_at = CURRENT_TIMESTAMP WHERE LOWER(username) = $4`, [cleanNew, hashed, role, cleanCurrent]);
    } else {
      await db.query(`UPDATE staff SET username = $1, role = $2 WHERE LOWER(username) = $3`, [cleanNew, role, cleanCurrent]);
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/staff/:username', async (req, res) => {
  try {
    await db.query(`DELETE FROM staff WHERE LOWER(username) = $1`, [req.params.username.trim().toLowerCase()]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/staff/change-password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  try {
    const result = await db.query('SELECT * FROM staff WHERE LOWER(username) = $1', [username.trim().toLowerCase()]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found.' });
    
    const isOldPasswordCorrect = await bcrypt.compare(oldPassword, result.rows[0].password);
    if (!isOldPasswordCorrect) return res.status(400).json({ error: 'Incorrect current password.' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE staff SET password = $1, password_changed_at = CURRENT_TIMESTAMP WHERE LOWER(username) = $2', [hashed, username.trim().toLowerCase()]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================================
// SECURITY MIDDLEWARE
// ==========================================
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Access denied.', forceLogout: true });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if(decoded.role !== 'patient') {
      const userResult = await db.query('SELECT password_changed_at FROM staff WHERE id = $1', [decoded.id]);
      if (userResult.rowCount > 0 && userResult.rows[0].password_changed_at) {
        const passwordChangedTime = new Date(userResult.rows[0].password_changed_at).getTime() / 1000;
        if (decoded.iat < passwordChangedTime) return res.status(401).json({ error: 'Session expired.', forceLogout: true });
      }
    }
    req.user = decoded; 
    next(); 
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token.', forceLogout: true });
  }
};

// ==========================================
// CLINICAL MODULES API (Relational Tables)
// ==========================================

// --- PATIENTS ---
app.get('/api/patients', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT id, name, email, phone, dob, age, gender, blood_group AS "bloodGroup", inits, color, created_at FROM patients ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.post('/api/patients', verifyToken, async (req, res) => {
  const { id, name, email, phone, dob, age, gender, bloodGroup, inits, color } = req.body;
  try {
    const query = `
      INSERT INTO patients (id, name, email, phone, dob, age, gender, blood_group, inits, color) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
      ON CONFLICT (id) DO UPDATE SET 
        name = EXCLUDED.name, email = EXCLUDED.email, phone = EXCLUDED.phone, 
        blood_group = EXCLUDED.blood_group, gender = EXCLUDED.gender
      RETURNING *;
    `;
    // FIX: Increased substring limits to 50 so "Not specified" doesn't get cut off
    const safeGender = (gender || 'Other').substring(0, 50);
    const safeBloodGroup = (bloodGroup || 'O+').substring(0, 50);
    const safePhone = (phone || '').substring(0, 20);

    const result = await db.query(query, [id, name, email, safePhone, dob || null, age || 25, safeGender, safeBloodGroup, inits || 'PT', color || 'bg-blue-500']);
    res.json({ success: true, patient: result.rows[0] });
  } catch (err) {
    console.error("Patient save error:", err);
    res.status(500).json({ error: 'Failed to save patient' });
  }
});
// --- APPOINTMENTS ---
app.get('/api/appointments', verifyToken, async (req, res) => {
  try {
    // FIX: Added TO_CHAR(date, 'YYYY-MM-DD') to strip the unwanted timestamp
    const result = await db.query(`SELECT id, patient_id AS "patientId", patient_name AS "patientName", doctor_id AS "doctorId", doctor_name AS "doctorName", TO_CHAR(date, 'YYYY-MM-DD') AS date, time, reason, status FROM appointments ORDER BY date DESC, time DESC`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});
app.post('/api/appointments', verifyToken, async (req, res) => {
  const { id, patientId, patientName, doctorId, doctorName, date, time, reason, status } = req.body;
  try {
    const query = `
      INSERT INTO appointments (id, patient_id, patient_name, doctor_id, doctor_name, date, time, reason, status) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
      ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, time = EXCLUDED.time
      RETURNING *;
    `;
    const result = await db.query(query, [id, patientId, patientName, doctorId, doctorName, date, time, reason || 'Checkup', status || 'Scheduled']);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Appointment save error:", err);
    res.status(500).json({ error: 'Failed to save appointment' });
  }
});

app.put('/api/appointments/:id', verifyToken, async (req, res) => {
  const { status, time, date, doctorId, doctorName } = req.body;
  try {
    const result = await db.query(
      `UPDATE appointments 
       SET status = COALESCE($1, status), 
           time = COALESCE($2, time), 
           date = COALESCE($3, date), 
           doctor_id = COALESCE($4, doctor_id), 
           doctor_name = COALESCE($5, doctor_name) 
       WHERE id = $6 RETURNING *`,
      [status, time, date, doctorId, doctorName, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});
app.delete('/api/appointments/:id', verifyToken, async (req, res) => {
  try {
    await db.query('DELETE FROM appointments WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Deletion failed' });
  }
});
// --- LAB REPORTS ---
app.get('/api/lab-reports', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT l.id, l.patient_id AS "patientId", p.name AS "patientName", l.test_name AS "testName", l.status, l.result, TO_CHAR(l.reported_date, 'YYYY-MM-DD') AS "reported" 
      FROM lab_records l 
      LEFT JOIN patients p ON l.patient_id = p.id 
      WHERE l.status = 'COMPLETED' 
      ORDER BY l.reported_date DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});
app.put('/api/lab-reports/:id', verifyToken, async (req, res) => {
  const { result, status } = req.body;
  try {
    const query = `
      UPDATE lab_records 
      SET result = $1, status = $2, reported_date = CURRENT_TIMESTAMP 
      WHERE id = $3 RETURNING *;
    `;
    const updated = await db.query(query, [result, status || 'COMPLETED', req.params.id]);
    res.json(updated.rows[0]);
  } catch (err) {
    console.error("Lab report update error:", err);
    res.status(500).json({ error: 'Failed to save report' });
  }
});
// --- LAB ORDERS ---
app.get('/api/lab-orders', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT l.id, l.patient_id AS "patientId", p.name AS "patientName", l.test_name AS "testName", l.status, l.result, TO_CHAR(l.reported_date, 'YYYY-MM-DD') AS "reported" 
      FROM lab_records l 
      LEFT JOIN patients p ON l.patient_id = p.id 
      WHERE l.status != 'COMPLETED' 
      ORDER BY l.id DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});
app.post('/api/lab-orders', verifyToken, async (req, res) => {
  // ... (keep this existing POST route exactly as it is) ...
  const { id, patientId, testName, status } = req.body;
  try {
    const query = `
      INSERT INTO lab_records (id, patient_id, test_name, status) 
      VALUES ($1, $2, $3, $4) 
      ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status
      RETURNING *;
    `;
    const result = await db.query(query, [id, patientId, testName, status || 'PENDING']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save lab order' });
  }
});

// ADD THIS MISSING ROUTE HERE:
app.put('/api/lab-orders/:id', verifyToken, async (req, res) => {
  const { status } = req.body;
  try {
    const result = await db.query(
      'UPDATE lab_records SET status = $1 WHERE id = $2 RETURNING *', 
      [status, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update lab order' });
  }
});
// --- PRESCRIPTIONS ---
app.get('/api/prescriptions', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT id, patient_id AS "patientId", patient_name AS "patientName", diagnosis, medications, total_cost AS "totalCost", status, created_at FROM prescriptions ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.post('/api/prescriptions', verifyToken, async (req, res) => {
  const { id, patientId, patientName, diagnosis, medications, totalCost, status } = req.body;
  try {
    const query = `
      INSERT INTO prescriptions (id, patient_id, patient_name, diagnosis, medications, total_cost, status) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) 
      ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status
      RETURNING *;
    `;
    const result = await db.query(query, [id, patientId, patientName, diagnosis, JSON.stringify(medications), totalCost || 0, status || 'PENDING']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save prescription' });
  }
});

app.put('/api/prescriptions/:id', verifyToken, async (req, res) => {
  const { status } = req.body;
  try {
    const result = await db.query('UPDATE prescriptions SET status = $1 WHERE id = $2 RETURNING *', [status, req.params.id]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update prescription' });
  }
});

// --- INVENTORY ---
app.get('/api/inventory', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT id, name, batch, expiry, quantity, unit_price AS "unitPrice" FROM inventory ORDER BY name ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.post('/api/inventory', verifyToken, async (req, res) => {
  const { id, name, batch, expiry, quantity, unitPrice } = req.body;
  try {
    const query = `
      INSERT INTO inventory (id, name, batch, expiry, quantity, unit_price) 
      VALUES ($1, $2, $3, $4, $5, $6) 
      ON CONFLICT (id) DO UPDATE SET quantity = EXCLUDED.quantity, unit_price = EXCLUDED.unit_price
      RETURNING *;
    `;
    const result = await db.query(query, [id, name, batch, expiry, quantity, unitPrice]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save inventory item' });
  }
});
// --- INVOICES ---
app.get('/api/invoices', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT i.id, i.patient_id AS "patientId", p.name AS "patientName", i.services, i.subtotal, i.gst AS "gstAmount", i.total_amount AS "totalAmount", i.status, TO_CHAR(i.invoice_date, 'YYYY-MM-DD') AS "date" 
      FROM invoices i 
      LEFT JOIN patients p ON i.patient_id = p.id 
      ORDER BY i.invoice_date DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});
app.post('/api/invoices', verifyToken, async (req, res) => {
  const { id, patientId, patientName, services, subtotal, gstAmount, totalAmount, status, date } = req.body;
  try {
    const query = `
      INSERT INTO invoices (id, patient_id, patient_name, services, subtotal, gst, total_amount, status, invoice_date) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE(NULLIF($9, ''), CURRENT_DATE)) 
      ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status
      RETURNING *;
    `;
    const result = await db.query(query, [id, patientId, patientName, services, subtotal, gstAmount || 0, totalAmount, status || 'PENDING', date]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Invoice save error:", err);
    res.status(500).json({ error: 'Failed to save invoice' });
  }
});
app.put('/api/invoices/:id', verifyToken, async (req, res) => {
  const { status } = req.body;
  try {
    const result = await db.query('UPDATE invoices SET status = $1 WHERE id = $2 RETURNING *', [status, req.params.id]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Invoice update failed' });
  }
});
// --- NOTIFICATIONS (NEW) ---
app.get('/api/notifications', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM notifications ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.post('/api/notifications', verifyToken, async (req, res) => {
  const { id, title, message, time, recipient, sender } = req.body;
  try {
    await db.query(
      `INSERT INTO notifications (id, title, message, time, recipient, sender) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
      [id, title, message, time, recipient, JSON.stringify(sender)]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save notification' });
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
    const systemPrompt = `You are a helpful hospital AI assistant for CarePoint HMS. User role: ${userRole}. Data: ${JSON.stringify(context)}.`;

    const completion = await groq.chat.completions.create({
      model: "openai/gpt-oss-20b", 
      messages: [{ role: "system", content: systemPrompt }, { role: "user", content: message }],
    });

    res.json({ reply: completion.choices[0].message.content });
  } catch (error) {
    res.status(500).json({ error: 'AI core is currently offline.' });
  }
});

// ==========================================
// WHATSAPP NOTIFICATION DISPATCH ROUTE
// ==========================================
app.post('/api/notify/whatsapp', verifyToken, async (req, res) => {
  const { phone, message } = req.body;
  if (!phone || !message) return res.status(400).json({ success: false, error: 'Phone and message required.' });

 try {
    const twilioClient = require('twilio')(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
    await twilioClient.messages.create({ 
      body: message, 
      from: 'whatsapp:+17372508034', 
      to: `whatsapp:+91${phone}` 
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to dispatch WhatsApp message.' });
  }
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`CarePoint Enterprise Cloud Server listening on port ${PORT}`);
});