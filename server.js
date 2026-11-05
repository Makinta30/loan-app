require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fetch = require('node-fetch');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Log a small, non-sensitive summary of environment on startup to aid remote debugging
const envSummary = {
  PORT: process.env.PORT || '3000',
  NODE_ENV: process.env.NODE_ENV || 'development',
  PAYSTACK_PUBLIC_KEY: process.env.PAYSTACK_PUBLIC_KEY ? 'set' : 'unset',
  PAYSTACK_SECRET_KEY: process.env.PAYSTACK_SECRET_KEY ? 'set' : 'unset',
  EMAIL_USER: process.env.EMAIL_USER ? 'set' : 'unset'
};
console.log('Env summary:', envSummary);

// Global handlers to log unexpected errors and exit with non-zero code so Render shows failure details
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err && err.stack ? err.stack : err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

// Ensure uploads directory exists
const uploadsDir = process.env.VERCEL ? path.join('/tmp', 'uploads') : path.join(__dirname, 'uploads');
const fs = require('fs');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage });

// Email setup (use environment variables or defaults)
const emailer = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your_email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your_app_password'
  }
});

const useInMemory = process.env.USE_IN_MEMORY_DB === 'true';
const DB_FILE = useInMemory ? ':memory:' : (process.env.VERCEL ? path.join('/tmp', 'data.db') : path.join(__dirname, 'data.db'));
console.log('Using SQLite DB:', useInMemory ? 'in-memory' : DB_FILE);
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Database connection error:', err);
  }
});

// Better error handling for database operations
db.on('error', (err) => {
  console.error('Database error:', err);
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    bvn TEXT,
    bvn_verified INTEGER DEFAULT 0
  )`, (err) => {
    if (err && !err.message.includes('already exists')) {
      console.error('Error creating users table:', err);
    }
  });

  db.run(`CREATE TABLE IF NOT EXISTS loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount INTEGER,
    deposit INTEGER,
    status TEXT DEFAULT 'pending',
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err && !err.message.includes('already exists')) {
      console.error('Error creating loans table:', err);
    }
  });

  db.run(`CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    loan_id INTEGER,
    reference TEXT,
    amount INTEGER,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err && !err.message.includes('already exists')) {
      console.error('Error creating payments table:', err);
    }
  });
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));


app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
}));

// Simple auth middleware
app.use((req, res, next) => {
  if (req.session && req.session.userId) {
    db.get('SELECT id, name, email, bvn_verified FROM users WHERE id = ?', [req.session.userId], (err, row) => {
      if (row) req.user = row;
      next();
    });
  } else next();
});

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => {
  if (req.user) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.get('/signup', (req, res) => res.render('signup'));
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.render('signup', { error: 'Email and password required' });
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, hash], function (err) {
    if (err) return res.render('signup', { error: 'Email already in use' });
    req.session.userId = this.lastID;
    res.redirect('/dashboard');
  });
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.render('login', { error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.render('login', { error: 'Invalid credentials' });
    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});

app.get('/forgot', (req, res) => res.render('forgot'));
app.post('/forgot', (req, res) => {
  const { email } = req.body;
  // Simple: generate token and show link (in production send email)
  const token = Math.random().toString(36).slice(2, 12);
  db.run('UPDATE users SET password_hash = password_hash WHERE email = ?', [email], function () {
    res.render('forgot', { message: `If that email exists we would send a link. Use reset token: ${token} (demo)` });
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.user });
});

app.get('/verify-bvn', requireAuth, (req, res) => {
  if (req.user.bvn_verified) return res.redirect('/apply');
  res.render('verify_bvn', { user: req.user });
});

app.post('/verify-bvn', requireAuth, (req, res) => {
  const { bvn } = req.body;
  // Simulate verification: valid if 11 digits
  if (!/^[0-9]{11}$/.test(bvn)) return res.render('verify_bvn', { error: 'BVN must be 11 digits' });
  db.run('UPDATE users SET bvn = ?, bvn_verified = 1 WHERE id = ?', [bvn, req.user.id], (err) => {
    res.redirect('/apply');
  });
});

app.get('/apply', requireAuth, (req, res) => {
  if (!req.user.bvn_verified) return res.redirect('/verify-bvn');
  // Render categories with more options
  const categories = [20000, 30000, 40000, 100000, 250000, 500000, 1000000];
  res.render('apply', { categories });
});

function calcDeposit(amount) {
  if (amount <= 50000) return Math.ceil(amount * 0.05);
  if (amount <= 200000) return Math.ceil(amount * 0.1);
  return Math.ceil(amount * 0.15);
}

app.post('/create-loan', requireAuth, (req, res) => {
  const amount = parseInt(req.body.amount, 10);
  if (!amount) return res.redirect('/apply');
  const deposit = calcDeposit(amount);
  db.run('INSERT INTO loans (user_id, amount, deposit, status) VALUES (?, ?, ?, ?)', [req.user.id, amount, deposit, 'awaiting_deposit'], function (err) {
    const loanId = this.lastID;
    res.render('payment', {
      loanId,
      amount,
      deposit,
      paystackKey: process.env.PAYSTACK_PUBLIC_KEY || 'PAYSTACK_PUBLIC_KEY',
      email: req.user.email || 'user@example.com'
    });
  });
});

app.post('/verify-payment', requireAuth, async (req, res) => {
  const { reference, loanId } = req.body;
  if (!reference || !loanId) return res.status(400).send('Missing');
  try {
    const secret = process.env.PAYSTACK_SECRET_KEY || 'PAYSTACK_SECRET_KEY';
    const resp = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${secret}` }
    });
    const json = await resp.json();
    if (json && json.data && json.data.status === 'success') {
      const amount = Math.round(json.data.amount / 100);
      db.run('INSERT INTO payments (loan_id, reference, amount, status) VALUES (?, ?, ?, ?)', [loanId, reference, amount, 'success']);
      db.run('UPDATE loans SET status = ? WHERE id = ?', ['deposit_paid', loanId]);
      return res.json({ ok: true, redirect: `/loan-form/${loanId}` });
    }
    res.json({ ok: false });
  } catch (e) {
    console.error('verify-payment error', e);
    res.json({ ok: false });
  }
});

app.post('/paystack/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['x-paystack-signature'];
  const secret = process.env.PAYSTACK_SECRET_KEY || 'PAYSTACK_SECRET_KEY';
  const hash = crypto.createHmac('sha512', secret).update(req.body).digest('hex');

  if (!signature || signature !== hash) {
    console.warn('Webhook signature mismatch');
    return res.status(401).send('Invalid signature');
  }

  const payload = JSON.parse(req.body.toString('utf8'));
  if (payload.event === 'charge.success') {
    const reference = payload.data.reference;
    const amount = Math.round(payload.data.amount / 100);
    const loanId = payload.data.metadata ? payload.data.metadata.loanId : null;
    if (loanId) {
      db.get('SELECT * FROM payments WHERE reference = ?', [reference], (err, payment) => {
        if (!payment) {
          db.run('INSERT INTO payments (loan_id, reference, amount, status) VALUES (?, ?, ?, ?)', [loanId, reference, amount, 'success']);
        }
        db.run('UPDATE loans SET status = ? WHERE id = ?', ['deposit_paid', loanId]);
      });
    }
  }

  res.sendStatus(200);
});

app.get('/loan-form/:loanId', requireAuth, (req, res) => {
  const loanId = req.params.loanId;
  db.get('SELECT * FROM loans WHERE id = ? AND user_id = ?', [loanId, req.user.id], (err, loan) => {
    if (!loan) return res.redirect('/apply');
    if (loan.status !== 'deposit_paid') return res.render('loan_form', { loan, error: 'Please complete deposit payment first' });
    res.render('loan_form', { loan });
  });
});

app.post('/submit-loan/:loanId', requireAuth, upload.single('passport'), (req, res) => {
  const loanId = req.params.loanId;
  const passportPath = req.file ? `/uploads/${req.file.filename}` : null;
  
  const details = {
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    dateOfBirth: req.body.dateOfBirth,
    state: req.body.state,
    lga: req.body.lga,
    bankName: req.body.bankName,
    bankAccount: req.body.bankAccount,
    reason: req.body.reason,
    passport: passportPath
  };
  
  db.run('UPDATE loans SET details = ?, status = ? WHERE id = ?', [JSON.stringify(details), 'submitted', loanId], (err) => {
    if (err) return res.render('success', { message: 'Error submitting application' });
    
    // Send email notification
    const mailOptions = {
      from: process.env.EMAIL_USER || 'noreply@loanapp.com',
      to: req.user.email,
      subject: '✅ Loan Application Received',
      html: `
        <h2>Your Loan Application Has Been Received</h2>
        <p>Dear ${details.firstName} ${details.lastName},</p>
        <p>Thank you for applying for a loan with Farmers Alliance & Business Boost!</p>
        <hr />
        <h3>Application Details:</h3>
        <ul>
          <li><strong>Loan ID:</strong> ${loanId}</li>
          <li><strong>State:</strong> ${details.state}</li>
          <li><strong>Reason:</strong> ${details.reason}</li>
          <li><strong>Bank Account:</strong> ${details.bankAccount}</li>
        </ul>
        <hr />
        <p>Our team will review your application and contact you within 2-3 business days.</p>
        <p>Best regards,<br/>Farmers Alliance & Business Boost Loan Team</p>
      `
    };
    
    emailer.sendMail(mailOptions, (err, info) => {
      if (err) console.log('Email error:', err);
      else console.log('Email sent:', info.response);
    });
    
    res.render('success', { message: 'Loan application submitted successfully! Check your email for confirmation.' });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.listen(PORT, () => {
  console.log(`Loan app running on port ${PORT}`);
  console.log(`Loan app running on http://0.0.0.0:${PORT}`);
}).on('error', (err) => {
  console.error('Server error:', err);
  process.exit(1);
});

