// ═══════════════════════════════════════════════════════════════
// AI DOCTOR WEBAPP — FULL BACKEND v2.0
// Auth + JWT + SQLite + Razorpay + Anthropic Proxy
// ═══════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'ai-doctor-jwt-secret-2024';
const TRIAL_DAYS = 3;
const MONTHLY_DAYS = 30;
const YEARLY_DAYS = 365;
const MONTHLY_PAISE = 99900;   // Rs 999
const YEARLY_PAISE = 799900;  // Rs 7999

// ── DATABASE ──────────────────────────────────────────────────
const dbPath = process.env.DB_PATH || './doctors.db';
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('❌ Database error:', err.message);
  else console.log('✅ Database connected');
});

// Helper for async queries
const dbRun = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) reject(err);
    else resolve(this);
  });
});

const dbGet = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => {
    if (err) reject(err);
    else resolve(row);
  });
});

const dbAll = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => {
    if (err) reject(err);
    else resolve(rows || []);
  });
});

const dbExec = (sql) => new Promise((resolve, reject) => {
  db.exec(sql, (err) => {
    if (err) reject(err);
    else resolve();
  });
});

dbExec(`
  CREATE TABLE IF NOT EXISTS doctors (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT NOT NULL,
    email                 TEXT UNIQUE NOT NULL,
    password              TEXT NOT NULL,
    qualification         TEXT NOT NULL,
    specialization        TEXT DEFAULT '',
    reg_number            TEXT DEFAULT '',
    phone                 TEXT DEFAULT '',
    role                  TEXT DEFAULT 'doctor',
    subscription_type     TEXT DEFAULT 'none',
    trial_start_date      TEXT,
    subscription_start_date TEXT,
    subscription_end_date TEXT,
    payment_status        TEXT DEFAULT 'unpaid',
    account_status        TEXT DEFAULT 'pending',
    razorpay_payment_id   TEXT DEFAULT '',
    razorpay_order_id     TEXT DEFAULT '',
    created_at            TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doctor_id INTEGER, razorpay_order_id TEXT, razorpay_payment_id TEXT,
    amount INTEGER, plan_type TEXT, status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doctor_id INTEGER NOT NULL,
    patient_key TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(doctor_id, patient_key)
  );
`).then(async () => {
  try { await dbExec("ALTER TABLE doctors ADD COLUMN session_token TEXT DEFAULT ''"); } catch(e){}
  console.log('✅ Tables ready');
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@aidoctor.com';
  const adminPass = process.env.ADMIN_PASSWORD || 'admin1234';
  const existingAdmin = await dbGet('SELECT id FROM doctors WHERE role=?', ['admin']);
  const hashed = await bcrypt.hash(adminPass, 12);
  if (!existingAdmin) {
    await dbRun("INSERT INTO doctors (name, email, password, qualification, role, account_status, subscription_type) VALUES ('Super Admin', ?, ?, 'Administrator', 'admin', 'active', 'lifetime')", [adminEmail, hashed]);
    console.log('✅ Permanent Admin Account Created');
  } else {
    await dbRun("UPDATE doctors SET email=?, password=? WHERE role='admin'", [adminEmail, hashed]);
    console.log('✅ Admin credentials synced with .env');
  }
}).catch(err => console.error('❌ Database init error:', err));

// ── RAZORPAY ──────────────────────────────────────────────────
const getRzpKeyId = () => (process.env.RAZORPAY_KEY_ID || 'rzp_test_DEMO').trim();
const getRzpSecret = () => (process.env.RAZORPAY_KEY_SECRET || 'PLACEHOLDER').trim();

const razorpay = new Razorpay({
  key_id: getRzpKeyId(),
  key_secret: getRzpSecret(),
});

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── MIDDLEWARE ─────────────────────────────────────────────────
async function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ error: 'no_token' });
  try { 
    const tokenStr = auth.slice(7);
    req.doctor = jwt.verify(tokenStr, JWT_SECRET); 
    const doc = await dbGet('SELECT session_token FROM doctors WHERE id=?', [req.doctor.id]);
    if (doc && doc.session_token && doc.session_token !== tokenStr) {
      return res.status(401).json({ error: 'token_invalid', detail: 'multiple_login' });
    }
    next(); 
  }
  catch { res.status(401).json({ error: 'token_invalid' }); }
}

function checkSub(req, res, next) {
  verifyToken(req, res, async () => {
    try {
      const doc = await dbGet('SELECT * FROM doctors WHERE id=?', [req.doctor.id]);
      if (!doc) return res.status(404).json({ error: 'not_found' });
      const now = new Date();
      if (doc.role !== 'admin') {
        if (doc.subscription_type === 'trial') {
          const end = new Date(doc.trial_start_date);
          end.setDate(end.getDate() + TRIAL_DAYS);
          if (now > end) {
            await dbRun("UPDATE doctors SET account_status='trial_expired' WHERE id=?", [doc.id]);
            return res.status(403).json({ error: 'trial_expired' });
          }
        }
        if (['monthly', 'yearly'].includes(doc.subscription_type) && doc.subscription_end_date) {
          if (now > new Date(doc.subscription_end_date)) {
            await dbRun("UPDATE doctors SET account_status='expired' WHERE id=?", [doc.id]);
            return res.status(403).json({ error: 'subscription_expired' });
          }
        }
        if (!['active', 'trial'].includes(doc.account_status))
          return res.status(403).json({ error: 'inactive' });
      }
      req.doctorData = doc;
      next();
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

// ════════════════════════════════════════════════════════════
// SIGNUP
// ════════════════════════════════════════════════════════════
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, qualification, specialization, reg_number, phone, plan } = req.body;
    if (!name || !email || !password || !qualification || !plan)
      return res.status(400).json({ error: 'Saare zaroori fields fill karein' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password minimum 6 characters' });
    if (await dbGet('SELECT id FROM doctors WHERE email=?', [email.toLowerCase()]))
      return res.status(409).json({ error: 'Yeh email pehle se registered hai — login karein' });

    const hashed = await bcrypt.hash(password, 12);
    const r = await dbRun(
      `INSERT INTO doctors (name,email,password,qualification,specialization,reg_number,phone)
       VALUES (?,?,?,?,?,?,?)`,
      [name.trim(), email.toLowerCase().trim(), hashed,
      qualification.trim(), specialization || '', reg_number || '', phone || '']
    );
    const docId = r.lastID;

    // FREE TRIAL
    if (plan === 'trial') {
      const ts = new Date().toISOString();
      const token = jwt.sign({ id: docId, email, name, qualification, specialization: specialization || '' }, JWT_SECRET, { expiresIn: '7d' });
      await dbRun(`UPDATE doctors SET subscription_type='trial',trial_start_date=?,account_status='active',session_token=? WHERE id=?`, [ts, token, docId]);
      const trialEnd = new Date(); trialEnd.setDate(trialEnd.getDate() + TRIAL_DAYS);
      return res.json({
        success: true, token, plan: 'trial', trialEnd: trialEnd.toISOString(),
        doctor: { id: docId, name, email, qualification, specialization: specialization || '' },
        message: `Dr. ${name}, 3-day free trial shuru ho gaya! ✅`
      });
    }

    // PAID PLAN — Razorpay order
    const amount = plan === 'monthly' ? MONTHLY_PAISE : YEARLY_PAISE;
    let order;
    try {
      order = await razorpay.orders.create({
        amount, currency: 'INR',
        receipt: `ord_${docId}`, notes: { doctor_id: `${docId}`, plan }
      });
      await dbRun('UPDATE doctors SET razorpay_order_id=? WHERE id=?', [order.id, docId]);
      await dbRun('INSERT INTO payments (doctor_id,razorpay_order_id,amount,plan_type) VALUES (?,?,?,?)', [docId, order.id, amount, plan]);
    } catch (e) {
      console.warn('Razorpay fallback (demo mode):', e.message);
      order = { id: `demo_${docId}_${Date.now()}`, amount, currency: 'INR' };
    }
    const tempToken = jwt.sign({ id: docId, email, name, qualification, pending: true }, JWT_SECRET, { expiresIn: '1h' });
    await dbRun('UPDATE doctors SET session_token=? WHERE id=?', [tempToken, docId]);
    res.json({
      success: true, needsPayment: true, tempToken, orderId: order.id, amount,
      doctor: { id: docId, name, email, qualification },
      razorpayKeyId: getRzpKeyId(),
      planLabel: plan === 'monthly' ? 'Monthly — Rs. 999/month' : 'Yearly — Rs. 7999/year'
    });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
// LOGIN
// ════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email aur password required' });
    const doc = await dbGet('SELECT * FROM doctors WHERE email=?', [email.toLowerCase().trim()]);
    if (!doc) return res.status(404).json({ error: 'Email registered nahi — pehle signup karein' });
    if (!await bcrypt.compare(password, doc.password)) return res.status(401).json({ error: 'Password galat hai' });

    const now = new Date();
    if (doc.role !== 'admin') {
      if (doc.subscription_type === 'trial') {
        const end = new Date(doc.trial_start_date); end.setDate(end.getDate() + TRIAL_DAYS);
        if (now > end) {
          await dbRun("UPDATE doctors SET account_status='trial_expired' WHERE id=?", [doc.id]);
          const amount = doc.subscription_type === 'yearly' ? YEARLY_PAISE : MONTHLY_PAISE;
          let order;
          try { order = await razorpay.orders.create({ amount, currency: 'INR', receipt: `renew_${doc.id}` }); }
          catch { order = { id: `demo_renew_${doc.id}_${Date.now()}` }; }
          return res.status(403).json({ error: 'trial_expired', doctorId: doc.id, name: doc.name, razorpayKeyId: getRzpKeyId(), orderId: order.id });
        }
      }
      if (['monthly', 'yearly'].includes(doc.subscription_type) && doc.subscription_end_date) {
        if (now > new Date(doc.subscription_end_date)) {
          await dbRun("UPDATE doctors SET account_status='expired' WHERE id=?", [doc.id]);
          const amount = doc.subscription_type === 'yearly' ? YEARLY_PAISE : MONTHLY_PAISE;
          let order;
          try { order = await razorpay.orders.create({ amount, currency: 'INR', receipt: `renew_${doc.id}` }); }
          catch { order = { id: `demo_renew_${doc.id}_${Date.now()}` }; }
          return res.status(403).json({ error: 'subscription_expired', doctorId: doc.id, name: doc.name, razorpayKeyId: getRzpKeyId(), orderId: order.id });
        }
      }
      if (!['active', 'trial'].includes(doc.account_status))
        return res.status(403).json({ error: 'Account inactive — support se milein' });
    }

    const token = jwt.sign({
      id: doc.id, email: doc.email, name: doc.name,
      qualification: doc.qualification, specialization: doc.specialization || ''
    }, JWT_SECRET, { expiresIn: '7d' });
    await dbRun('UPDATE doctors SET session_token=? WHERE id=?', [token, doc.id]);

    let trialDaysLeft = null, subscriptionDaysLeft = null;
    if (doc.subscription_type === 'trial') {
      const end = new Date(doc.trial_start_date); end.setDate(end.getDate() + TRIAL_DAYS);
      trialDaysLeft = Math.ceil((end - now) / (864e5));
    }
    if (doc.subscription_end_date) subscriptionDaysLeft = Math.ceil((new Date(doc.subscription_end_date) - now) / (864e5));

    res.json({
      success: true, token, doctor: {
        id: doc.id, name: doc.name, email: doc.email,
        qualification: doc.qualification, specialization: doc.specialization || '',
        plan: doc.subscription_type, trialDaysLeft, subscriptionDaysLeft,
        subscriptionEnd: doc.subscription_end_date
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET ME ────────────────────────────────────────────────────
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const doc = await dbGet('SELECT id,name,email,qualification,specialization,subscription_type,account_status,trial_start_date,subscription_end_date,role FROM doctors WHERE id=?', [req.doctor.id]);
    if (!doc) return res.status(404).json({ error: 'not_found' });
    const now = new Date();
    let trialDaysLeft = null, subscriptionDaysLeft = null;
    if (doc.role !== 'admin') {
      if (doc.subscription_type === 'trial' && doc.trial_start_date) {
        const e = new Date(doc.trial_start_date); e.setDate(e.getDate() + TRIAL_DAYS);
        if (now > e) return res.status(403).json({ error: 'trial_expired' });
        trialDaysLeft = Math.ceil((e - now) / (864e5));
      }
      if (doc.subscription_end_date) {
        const e = new Date(doc.subscription_end_date);
        if (now > e) return res.status(403).json({ error: 'subscription_expired' });
        subscriptionDaysLeft = Math.ceil((e - now) / (864e5));
      }
    }
    res.json({ doctor: { ...doc, trialDaysLeft, subscriptionDaysLeft } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PAYMENT VERIFY ────────────────────────────────────────────
app.post('/api/payment/verify', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, doctorId, plan, demo } = req.body;
    if (!demo && getRzpSecret()) {
      const sig = crypto.createHmac('sha256', getRzpSecret())
        .update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
      if (sig !== razorpay_signature) return res.status(400).json({ error: 'Signature invalid' });
    }
    const days = plan === 'monthly' ? MONTHLY_DAYS : YEARLY_DAYS;
    const start = new Date().toISOString();
    const end = new Date(); end.setDate(end.getDate() + days);
    await dbRun(`UPDATE doctors SET subscription_type=?,subscription_start_date=?,subscription_end_date=?,
      payment_status='paid',account_status='active',razorpay_payment_id=?,razorpay_order_id=? WHERE id=?`,
      [plan, start, end.toISOString(), razorpay_payment_id || 'demo', razorpay_order_id || 'demo', doctorId]);
    await dbRun(`UPDATE payments SET status='paid',razorpay_payment_id=? WHERE razorpay_order_id=?`,
      [razorpay_payment_id || 'demo', razorpay_order_id || 'demo']);
    const doc = await dbGet('SELECT * FROM doctors WHERE id=?', [doctorId]);
    const token = jwt.sign({
      id: doc.id, email: doc.email, name: doc.name,
      qualification: doc.qualification, specialization: doc.specialization || ''
    }, JWT_SECRET, { expiresIn: '7d' });
    await dbRun('UPDATE doctors SET session_token=? WHERE id=?', [token, doctorId]);
    res.json({
      success: true, token,
      doctor: { id: doc.id, name: doc.name, qualification: doc.qualification, plan, subscriptionEnd: end.toISOString() },
      message: `Payment successful! Dr. ${doc.name} ka ${plan} plan activate ho gaya! 🎉`
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PATIENT SYNC ──────────────────────────────────────────────
app.get('/api/patients', verifyToken, async (req, res) => {
  try {
    const rows = await dbAll('SELECT patient_key, data FROM patients WHERE doctor_id=?', [req.doctor.id]);
    const records = {};
    rows.forEach(r => { try { records[r.patient_key] = JSON.parse(r.data); } catch (e) { } });
    res.json({ records });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients', verifyToken, async (req, res) => {
  try {
    const { patient_key, data } = req.body;
    if (!patient_key || !data) return res.status(400).json({ error: 'Missing data' });
    await dbRun(`INSERT INTO patients (doctor_id, patient_key, data, updated_at) 
      VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(doctor_id, patient_key) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`,
      [req.doctor.id, patient_key, JSON.stringify(data)]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients/delete', verifyToken, async (req, res) => {
  try {
    const { patient_key } = req.body;
    await dbRun('DELETE FROM patients WHERE doctor_id=? AND patient_key=?', [req.doctor.id, patient_key]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients/clear', verifyToken, async (req, res) => {
  try {
    await dbRun('DELETE FROM patients WHERE doctor_id=?', [req.doctor.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CREATE ORDER (renewal) ─────────────────────────────────────
app.post('/api/payment/create-order', verifyToken, async (req, res) => {
  try {
    const { plan } = req.body;
    const amount = plan === 'monthly' ? MONTHLY_PAISE : YEARLY_PAISE;
    let order;
    try { order = await razorpay.orders.create({ amount, currency: 'INR', receipt: `renew_${req.doctor.id}` }); }
    catch { order = { id: `demo_renew_${req.doctor.id}_${Date.now()}`, amount }; }
    res.json({ orderId: order.id, amount, razorpayKeyId: getRzpKeyId() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── AI CHAT PROXY (subscription protected) ────────────────────
app.post('/api/chat', checkSub, async (req, res) => {
  try {
    const { model, max_tokens, system, messages } = req.body;
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'Groq API key not set in .env' });
    
    // Groq format requires system prompt as part of messages array (OpenAI compatible)
    const openAiMessages = [
      { role: 'system', content: system || '' },
      ...(messages || [])
    ];

    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        'Authorization': `Bearer ${apiKey}` 
      },
      body: JSON.stringify({ 
        model: 'llama-3.3-70b-versatile', // Using Groq's active Llama 3.3 70B model
        max_tokens: max_tokens || 1000, 
        messages: openAiMessages 
      }),
    });
    
    const data = await r.json();
    
    // Map Groq (OpenAI style) response back to the format frontend expects (Anthropic style)
    if (data.choices && data.choices[0] && data.choices[0].message) {
      res.json({
        content: [{ text: data.choices[0].message.content }]
      });
    } else {
      res.json(data); // if error
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/auth', (req, res) => res.sendFile(path.join(__dirname, 'auth.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`✅ AI Doctor Server — port ${PORT}`);
  console.log(`   App:  http://localhost:${PORT}`);
  console.log(`   Auth: http://localhost:${PORT}/auth`);
});
// Restarted server for .env updates
// Restarted again for latest key update
// Restarted for Groq key
