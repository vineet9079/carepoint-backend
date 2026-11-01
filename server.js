require('dotenv').config();
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be configured with at least 32 characters.');
}
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');

const app = express();

// ==========================================
// EMAIL FORMATTING HELPERS
// ==========================================
const crypto = require('crypto');

// Repair Markdown-style links accidentally placed inside HTML href attributes.
function repairEmailLinks(html) {
  return String(html || '').replace(
    /href=(['"] )?\[?(https?:\/\/[^\]\s)"']+)\]?\((https?:\/\/[^)\s"']+)\)\1/gi,
    (match, quote, displayedUrl, targetUrl) => `href="${(targetUrl || displayedUrl).replace(/&amp;/g, '&')}"`
  ).replace(
    /href=(['"])\[(https?:\/\/[^\]\s]+)\]\((https?:\/\/[^)\s]+)\)\1/gi,
    (match, quote, displayedUrl, targetUrl) => `href="${(targetUrl || displayedUrl).replace(/&amp;/g, '&')}"`
  );
}

// Convert HTML into readable plain text and retain the destinations of links.
function htmlToPlainText(html) {
  return String(html || '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi,
      (match, url, label) => `${label.replace(/<[^>]*>/g, '').trim()} (${url})`)
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|h1|h2|h3|li)>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function base64MimePart(value) {
  return Buffer.from(String(value), 'utf8')
    .toString('base64')
    .match(/.{1,76}/g)
    ?.join('\r\n') || '';
}

// Build a standards-compliant plain-text + HTML email for Gmail API.
function buildGmailRawMessage({ to, from, subject, html }) {
  const cleanTo = String(to || '').replace(/[\r\n]+/g, '').trim();
  const cleanFrom = String(from || '').replace(/[\r\n]+/g, '').trim();
  const cleanSubject = String(subject || '').replace(/[\r\n]+/g, ' ').trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanTo) ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanFrom)) {
    throw new Error('Invalid email address in message headers.');
  }

  const repairedHtml = repairEmailLinks(html);
  const plainText = htmlToPlainText(repairedHtml) || 'Please view this message in an HTML-capable email client.';
  const boundary = `carepoint_${crypto.randomBytes(16).toString('hex')}`;
  const encodedSubject = `=?UTF-8?B?${Buffer.from(cleanSubject, 'utf8').toString('base64')}?=`;

  const mimeMessage = [
    `To: ${cleanTo}`,
    `From: "CarePoint HMS" <${cleanFrom}>`,
    `Subject: ${encodedSubject}`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    base64MimePart(plainText),
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    base64MimePart(repairedHtml),
    '',
    `--${boundary}--`,
    ''
  ].join('\r\n');

  return Buffer.from(mimeMessage, 'utf8').toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

app.use(cors());
app.use(express.json({ limit: '256kb' }));

// Database Connection (Neon DB)
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

db.on('error', (error) => {
  console.error('[DATABASE] Unexpected idle client error:', error);
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
    console.error('Staff login error:', error);
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
    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new Error(tokenData.error_description || tokenData.error || 'Failed to get access token');
    }

    const safeOtp = String(otp).replace(/[&<>"']/g, char => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[char]));

    const otpHtml = `
      <div style="font-family:Arial,sans-serif;padding:20px;max-width:600px;margin:auto;">
        <h2 style="color:#4355B9;">CarePoint HMS</h2>
        <p>Your secure login verification code is:</p>
        <h1 style="letter-spacing:5px;">${safeOtp}</h1>
        <p>If you did not request this code, you can ignore this email.</p>
        <p style="color:#777;font-size:12px;">Automated CarePoint notification.</p>
      </div>
    `;

    const base64EncodedEmail = buildGmailRawMessage({
      to: email,
      from: process.env.EMAIL_USER,
      subject: 'CarePoint HMS - Secure Login Verification Code',
      html: otpHtml
    });

    const sendResponse = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: base64EncodedEmail })
    });

    if (!sendResponse.ok) throw new Error(await sendResponse.text());
    res.json({ success: true, message: 'OTP dispatched securely via Gmail HTTPS API.' });
  } catch (error) {
    console.error('[OTP EMAIL] Dispatch failed:', error.message);
    res.status(500).json({ success: false, error: 'Failed to send OTP.' });
  }
});

// EMAIL NOTIFICATION ROUTE IS REGISTERED AFTER verifyToken IS DEFINED.

// ==========================================
// GENERATE SECURE PATIENT TOKEN
// ==========================================
app.post('/api/auth/patient-token', async (req, res) => {
  const identity = String(req.body?.email || '').trim();
  if (!identity) {
    return res.status(400).json({ success: false, error: 'Email or phone is required.' });
  }

  try {
    const result = await db.query(
      `SELECT * FROM patients
       WHERE LOWER(email) = LOWER($1) OR phone = $1
       LIMIT 1`,
      [identity]
    );

    const patient = result.rows[0] || null;
    const normalizedEmail = patient?.email || (
      identity.includes('@') ? identity.toLowerCase() : null
    );
    const token = jwt.sign(
      { id: patient?.id || null, email: normalizedEmail, role: 'patient' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Keep the existing OTP -> profile-registration flow working for new patients.
    return res.json({ success: true, token, patient });
  } catch (err) {
    console.error('Patient token generation error:', err.message);
    return res.status(500).json({ success: false, error: 'Server error generating token.' });
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
  if (!authHeader || !/^Bearer\s+\S+$/i.test(authHeader)) {
    return res.status(401).json({ error: 'Access denied.', forceLogout: true });
  }

  const token = authHeader.split(/\s+/)[1];
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
// SECURE EMAIL NOTIFICATIONS (GMAIL API)
// ==========================================
// Staff may send to a registered patient's address. Patient JWTs are restricted
// to the email address on that patient's own database record.
app.post('/api/notify/email', verifyToken, async (req, res) => {
  const requestId = `mail-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const { patientId, email, subject, htmlMessage } = req.body || {};
  const requestedEmail = String(email || '').trim().toLowerCase();
  const cleanSubject = String(subject || '').replace(/[\r\n]+/g, ' ').trim();

  console.log('[EMAIL]', requestId, 'request received', {
    actorRole: req.user?.role,
    patientId: patientId || null,
    hasEmail: Boolean(requestedEmail),
    hasSubject: Boolean(cleanSubject),
    htmlLength: typeof htmlMessage === 'string' ? htmlMessage.length : 0
  });

  if ((!patientId && !requestedEmail) || !cleanSubject || typeof htmlMessage !== 'string' || !htmlMessage.trim()) {
    return res.status(400).json({ success: false, error: 'Patient ID or email, subject and HTML message are required.', requestId });
  }
  if (requestedEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(requestedEmail)) {
    return res.status(400).json({ success: false, error: 'A valid recipient email is required.', requestId });
  }
  if (htmlMessage.length > 100000) {
    return res.status(413).json({ success: false, error: 'Email message is too large.', requestId });
  }

  let patient = null;
  let dispatchLogId = null;
  try {
    // Resolve recipient from Neon, not from an untrusted browser-supplied email alone.
    const patientResult = patientId
      ? await db.query('SELECT id, name, email FROM patients WHERE id = $1 LIMIT 1', [String(patientId)])
      : await db.query('SELECT id, name, email FROM patients WHERE LOWER(email) = $1 LIMIT 1', [requestedEmail]);

    patient = patientResult.rows[0] || null;
    if (!patient || !patient.email) {
      console.error('[EMAIL]', requestId, 'patient/email lookup failed', { patientId: patientId || null });
      return res.status(404).json({ success: false, error: 'No registered patient email was found for this notification.', requestId });
    }

    const recipient = String(patient.email).trim().toLowerCase();
    if (requestedEmail && requestedEmail !== recipient) {
      return res.status(409).json({ success: false, error: 'The supplied email does not match the registered patient email.', requestId });
    }

    const role = String(req.user?.role || '').toLowerCase();
    if (role === 'patient') {
      const tokenPatientId = req.user?.id ? String(req.user.id) : '';
      const tokenEmail = String(req.user?.email || '').trim().toLowerCase();
      const authenticatedPatient = tokenPatientId
        ? await db.query('SELECT id, email FROM patients WHERE id = $1 LIMIT 1', [tokenPatientId])
        : await db.query('SELECT id, email FROM patients WHERE LOWER(email) = $1 LIMIT 1', [tokenEmail]);
      const ownPatient = authenticatedPatient.rows[0];
      if (!ownPatient || String(ownPatient.email || '').trim().toLowerCase() !== recipient ||
          (tokenPatientId && String(ownPatient.id) !== tokenPatientId) || (tokenEmail && tokenEmail !== recipient)) {
        return res.status(403).json({ success: false, error: 'Patient accounts can only send notifications to their own registered email.', requestId });
      }
    } else if (!req.user?.id) {
      return res.status(403).json({ success: false, error: 'A valid staff account is required.', requestId });
    }

    const requiredEnv = ['CLIENT_ID', 'CLIENT_SECRET', 'REFRESH_TOKEN', 'EMAIL_USER'];
    const missingEnv = requiredEnv.filter(key => !process.env[key]);
    if (missingEnv.length) {
      console.error('[EMAIL]', requestId, 'missing Render environment variables:', missingEnv);
      return res.status(503).json({ success: false, error: 'Email service is not configured on the server.', requestId });
    }

    // Dispatch history is best-effort so a missing optional log table never blocks mail.
    try {
      const logResult = await db.query(
        `INSERT INTO email_dispatch_logs (patient_id, recipient_email, subject, notification_type, status)
         VALUES ($1, $2, $3, $4, 'PENDING') RETURNING id`,
        [
          patient.id,
          recipient,
          cleanSubject,
          /payment due/i.test(cleanSubject) ? 'DUE' :
          /payment confirmation/i.test(cleanSubject) ? 'PAYMENT' :
          /invoice generated/i.test(cleanSubject) ? 'INVOICE' :
          /medical order received/i.test(cleanSubject) ? 'ORDER' :
          /lab report available/i.test(cleanSubject) ? 'REPORT' : 'GENERAL'
        ]
      );
      dispatchLogId = logResult.rows[0]?.id || null;
    } catch (logError) {
      console.error('[EMAIL]', requestId, 'dispatch-log insert failed (mail will continue):', logError.message);
    }

    console.log('[EMAIL]', requestId, 'refreshing Google OAuth access token');
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
    const tokenText = await tokenResponse.text();
    let tokenData = {};
    try { tokenData = tokenText ? JSON.parse(tokenText) : {}; } catch { /* handled below */ }
    if (!tokenResponse.ok || !tokenData.access_token) {
      const oauthMessage = tokenData.error_description || tokenData.error || `HTTP ${tokenResponse.status}`;
      console.error('[EMAIL]', requestId, 'Google OAuth refresh failed:', oauthMessage);
      if (dispatchLogId) await db.query(
        `UPDATE email_dispatch_logs SET status = 'FAILED', error_message = $1 WHERE id = $2`,
        [String(oauthMessage).slice(0, 2000), dispatchLogId]
      ).catch(err => console.error('[EMAIL]', requestId, 'failed to update dispatch log:', err.message));
      return res.status(502).json({ success: false, error: 'Google authentication failed. Verify OAuth credentials and Gmail API permissions.', requestId });
    }
    console.log('[EMAIL]', requestId, 'OAuth access token refreshed');

    const senderEmail = String(process.env.EMAIL_USER).trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(senderEmail)) {
      console.error('[EMAIL]', requestId, 'EMAIL_USER is invalid');
      return res.status(503).json({ success: false, error: 'Email sender configuration is invalid.', requestId });
    }

    const raw = buildGmailRawMessage({
      to: recipient,
      from: senderEmail,
      subject: cleanSubject,
      html: htmlMessage
    });

    if (!raw || /[^A-Za-z0-9_-]/.test(raw)) {
      throw new Error('Gmail MIME raw payload failed base64url validation.');
    }

    console.log('[EMAIL]', requestId, 'calling Gmail messages.send', { recipient, rawLength: raw.length });
    const sendResponse = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ raw })
    });
    const sendText = await sendResponse.text();
    let sendData = {};
    try { sendData = sendText ? JSON.parse(sendText) : {}; } catch { sendData = { message: sendText }; }

    if (!sendResponse.ok || !sendData.id) {
      const gmailMessage = sendData.error?.message || sendData.message || `HTTP ${sendResponse.status}`;
      console.error('[EMAIL]', requestId, 'Gmail API rejected message:', {
        status: sendResponse.status,
        statusText: sendResponse.statusText,
        error: gmailMessage
      });
      if (dispatchLogId) await db.query(
        `UPDATE email_dispatch_logs SET status = 'FAILED', error_message = $1 WHERE id = $2`,
        [String(gmailMessage).slice(0, 2000), dispatchLogId]
      ).catch(err => console.error('[EMAIL]', requestId, 'failed to update dispatch log:', err.message));
      return res.status(502).json({ success: false, error: 'Gmail could not send the notification.', details: gmailMessage, requestId });
    }

    if (dispatchLogId) await db.query(
      `UPDATE email_dispatch_logs SET status = 'SENT', gmail_message_id = $1, sent_at = CURRENT_TIMESTAMP WHERE id = $2`,
      [sendData.id, dispatchLogId]
    ).catch(err => console.error('[EMAIL]', requestId, 'sent but dispatch-log update failed:', err.message));

    console.log('[EMAIL]', requestId, 'Gmail accepted message', {
      patientId: patient.id,
      messageId: sendData.id,
      threadId: sendData.threadId || null
    });
    return res.json({ success: true, message: 'Notification email dispatched.', messageId: sendData.id, requestId });
  } catch (error) {
    console.error('[EMAIL]', requestId, 'dispatch exception:', error.stack || error.message || error);
    if (dispatchLogId) await db.query(
      `UPDATE email_dispatch_logs SET status = 'FAILED', error_message = $1 WHERE id = $2`,
      [String(error.message || error).slice(0, 2000), dispatchLogId]
    ).catch(err => console.error('[EMAIL]', requestId, 'failed to update dispatch log:', err.message));
    return res.status(500).json({ success: false, error: 'Failed to dispatch notification email.', requestId });
  }
});

// ==========================================
// CLINICAL MODULES API (Relational Tables)
// ==========================================

// --- PATIENTS ---
app.get('/api/patients', verifyToken, async (req, res) => {
  try {
    // FIX: Added TO_CHAR to format the Date of Birth perfectly
    const result = await db.query(`SELECT id, name, email, phone, TO_CHAR(dob, 'YYYY-MM-DD') AS dob, age, gender, blood_group AS "bloodGroup", inits, color, created_at FROM patients ORDER BY created_at DESC`);
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
// --- DELETE PATIENT ---
app.delete('/api/patients/:id', verifyToken, async (req, res) => {
  try {
    await db.query('DELETE FROM patients WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Deletion failed' });
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
    console.error('Lab order save error:', err);
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
    console.error('Prescription save error:', err);
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
app.put('/api/inventory/:id', verifyToken, async (req, res) => {
  const { name, batch, expiry, quantity, unitPrice } = req.body;
  try {
    const result = await db.query(
      `UPDATE inventory 
       SET name = COALESCE($1, name), 
           batch = COALESCE($2, batch), 
           expiry = COALESCE($3, expiry), 
           quantity = COALESCE($4, quantity), 
           unit_price = COALESCE($5, unit_price) 
       WHERE id = $6 RETURNING *`,
      [name, batch, expiry, quantity, unitPrice, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update inventory item' });
  }
});
// --- INVOICES ---
app.get('/api/invoices', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, patient_id AS "patientId", patient_name AS "patientName", services, subtotal, gst AS "gstAmount", total_amount AS "totalAmount", status, TO_CHAR(invoice_date, 'YYYY-MM-DD') AS "date" 
      FROM invoices 
      ORDER BY invoice_date DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json([]);
  }
});
// ==========================================
// INVOICES - FIXED SQL ROUTE
// ==========================================
app.post('/api/invoices', verifyToken, async (req, res) => {
  const { id, patientId, patientName, services, subtotal, gstAmount, totalAmount, status, date } = req.body;
  try {
    // FIX: Removed the COALESCE function that caused the Postgres type mismatch crash
    const query = `
      INSERT INTO invoices (id, patient_id, patient_name, services, subtotal, gst, total_amount, status, invoice_date) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
      ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status
      RETURNING *;
    `;
    // Safely assign the date in JavaScript to guarantee it formats correctly
    const safeDate = date || new Date().toISOString().split('T')[0];
    
    const result = await db.query(query, [id, patientId, patientName, services || 'Medical Services', subtotal, gstAmount || 0, totalAmount, status || 'PENDING', safeDate]);
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
    console.error('Invoice update error:', err);
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
app.post('/api/chat', async (req, res) => {
  try {
    if (!process.env.GROQ_API_KEY) {
      return res.status(503).json({ error: 'AI service is not configured.' });
    }
    const groq = new OpenAI({
      apiKey: process.env.GROQ_API_KEY,
      baseURL: "https://api.groq.com/openai/v1",
    });
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