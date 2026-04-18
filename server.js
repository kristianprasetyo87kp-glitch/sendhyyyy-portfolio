'use strict';

require('dotenv').config();

const express   = require('express');
const path      = require('path');
const fs        = require('fs');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const multer    = require('multer');
const nodemailer= require('nodemailer');
const { DatabaseSync } = require('node:sqlite');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
//  Paths
// ─────────────────────────────────────────────
const ROOT = __dirname;

// PERSISTENT_DIR: set ke /persistent di Railway (volume mount).
// Kalau tidak diset (lokal), fallback ke ROOT supaya behaviour tidak berubah.
const PERSIST  = process.env.PERSISTENT_DIR || ROOT;
const DATA_DIR = path.join(PERSIST, 'data');
const DB_FILE  = path.join(DATA_DIR, 'submissions.db');

// Upload destination: foto, favicon, thumbs → volume (persistent di Railway)
const UPLOADS_DIR = path.join(PERSIST, 'public');

// Bundled / read-only assets (dalam repo)
const PUBLIC_DIR = path.join(ROOT, 'public');
const ADMIN_DIR  = path.join(ROOT, 'admin');

// content.json dibaca/ditulis dari volume; jika belum ada (fresh volume), copy dari bundled default
const DEFAULT_CONTENT = path.join(ROOT, 'data', 'content.json');
const CONTENT_FILE    = path.join(DATA_DIR, 'content.json');
if (!fs.existsSync(CONTENT_FILE)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.copyFileSync(DEFAULT_CONTENT, CONTENT_FILE);
}

// Pastikan folder uploads ada
fs.mkdirSync(path.join(UPLOADS_DIR, 'thumbs'), { recursive: true });

// ─────────────────────────────────────────────
//  SQLite — built-in Node.js v22.5+ (node:sqlite)
// ─────────────────────────────────────────────
const db = new DatabaseSync(DB_FILE);
db.exec(`
  CREATE TABLE IF NOT EXISTS submissions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT,
    brand        TEXT,
    budget       TEXT,
    email        TEXT,
    message      TEXT,
    ip           TEXT,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// ─────────────────────────────────────────────
//  Nodemailer transporter
// ─────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ─────────────────────────────────────────────
//  Multer — favicon upload
// ─────────────────────────────────────────────
const faviconStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.ico';
    cb(null, 'favicon' + ext);
  }
});
const uploadFavicon = multer({
  storage: faviconStorage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['.ico', '.png', '.svg'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Hanya file .ico, .png, atau .svg yang diizinkan'));
  }
});

// ─────────────────────────────────────────────
//  Multer — portfolio thumbnail upload
// ─────────────────────────────────────────────
const THUMBS_DIR = path.join(UPLOADS_DIR, 'thumbs');
// THUMBS_DIR dibuat saat startup (lihat blok Paths di atas)

const thumbStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, THUMBS_DIR),
  filename:    (req, file, cb) => {
    const id  = req.params.id || 'unknown';
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    // Hapus file lama dengan id yang sama
    ['.jpg', '.jpeg', '.png', '.webp'].forEach(e => {
      const old = path.join(THUMBS_DIR, 'thumb-' + id + e);
      if (fs.existsSync(old)) fs.unlinkSync(old);
    });
    cb(null, 'thumb-' + id + ext);
  }
});
const uploadThumb = multer({
  storage: thumbStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Hanya file .jpg, .png, atau .webp yang diizinkan'));
  }
});

// ─────────────────────────────────────────────
//  Multer — about photo upload
// ─────────────────────────────────────────────
const photoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    // Hapus foto lama dengan ekstensi berbeda sebelum simpan yang baru
    ['.jpg', '.jpeg', '.png', '.webp'].forEach(e => {
      const old = path.join(UPLOADS_DIR, 'photo' + e);
      if (fs.existsSync(old) && e !== ext) fs.unlinkSync(old);
    });
    cb(null, 'photo' + ext);
  }
});
const uploadPhoto = multer({
  storage: photoStorage,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Hanya file .jpg, .png, atau .webp yang diizinkan'));
  }
});

// ─────────────────────────────────────────────
//  Middleware
// ─────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Static: bundled assets (icons, placeholder images, dll)
app.use('/public', express.static(PUBLIC_DIR));
// Static: uploaded files (foto, favicon, thumbs) — dari volume jika di Railway
app.use('/public', express.static(UPLOADS_DIR));

// ─────────────────────────────────────────────
//  JWT Auth Middleware
// ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token diperlukan' });
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token tidak valid atau expired' });
  }
}

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────
function readContent() {
  return JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
}
function writeContent(data) {
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// ─────────────────────────────────────────────
//  PUBLIC API
// ─────────────────────────────────────────────

// GET /api/content — kembalikan content.json ke frontend
app.get('/api/content', (req, res) => {
  try {
    res.json(readContent());
  } catch (e) {
    res.status(500).json({ error: 'Gagal membaca konten' });
  }
});

// POST /api/submit — simpan submission + kirim email
app.post('/api/submit', async (req, res) => {
  const { name, brand, budget, email, message } = req.body;

  // Basic validation
  if (!name || !email) {
    return res.status(400).json({ error: 'Nama dan email wajib diisi' });
  }

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

  // 1. Simpan ke SQLite
  try {
    db.prepare(`
      INSERT INTO submissions (name, brand, budget, email, message, ip)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(name, brand || '', budget || '', email, message || '', ip);
  } catch (e) {
    console.error('DB Error:', e.message);
    return res.status(500).json({ error: 'Gagal menyimpan pesan' });
  }

  // 2. Kirim email notifikasi
  const htmlEmail = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#333">
      <div style="background:#1C1510;padding:24px;text-align:center">
        <h2 style="color:#C5958A;font-size:20px;margin:0;font-family:Georgia,serif">
          New Inquiry — Sendhy Portfolio
        </h2>
      </div>
      <div style="padding:28px;border:1px solid #e5e5e5;border-top:none">
        <table style="width:100%;border-collapse:collapse">
          <tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;width:130px;color:#888;font-size:13px">Name</td>
              <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px"><strong>${name}</strong></td></tr>
          <tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#888;font-size:13px">Email</td>
              <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px"><a href="mailto:${email}" style="color:#C5958A">${email}</a></td></tr>
          <tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#888;font-size:13px">Brand</td>
              <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px">${brand || '—'}</td></tr>
          <tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#888;font-size:13px">Budget</td>
              <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px">${budget || '—'}</td></tr>
          <tr><td style="padding:10px 0;color:#888;font-size:13px;vertical-align:top">Message</td>
              <td style="padding:10px 0;font-size:14px;line-height:1.6">${(message || '—').replace(/\n/g, '<br>')}</td></tr>
        </table>
      </div>
      <div style="padding:16px;background:#f9f9f9;text-align:center;font-size:12px;color:#aaa">
        Dikirim via Sendhy Portfolio Contact Form
      </div>
    </div>
  `;

  try {
    await transporter.sendMail({
      from:    `"Sendhy Portfolio" <${process.env.EMAIL_USER}>`,
      to:      process.env.EMAIL_TO,
      replyTo: email,
      subject: `New Inquiry from ${name}${brand ? ' — ' + brand : ''}`,
      html:    htmlEmail
    });
  } catch (e) {
    // Email gagal tapi submission sudah tersimpan — tetap sukses ke user
    console.error('Email Error:', e.message);
  }

  res.json({ success: true, message: 'Pesan terkirim. Terima kasih!' });
});

// ─────────────────────────────────────────────
//  ADMIN API (JWT required)
// ─────────────────────────────────────────────

// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password diperlukan' });

  const match = await bcrypt.compare(password, await bcrypt.hash(process.env.ADMIN_PASSWORD, 10))
    .catch(() => false);

  // Simpler direct compare (no bcrypt hash needed for single password)
  const correct = password === process.env.ADMIN_PASSWORD;
  if (!correct) return res.status(401).json({ error: 'Password salah' });

  const token = jwt.sign({ admin: true }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// GET /api/admin/content
app.get('/api/admin/content', requireAuth, (req, res) => {
  try {
    res.json(readContent());
  } catch {
    res.status(500).json({ error: 'Gagal membaca konten' });
  }
});

// PUT /api/admin/content
app.put('/api/admin/content', requireAuth, (req, res) => {
  try {
    const data = req.body;
    // Basic structure validation
    if (!data.about || !data.social || !data.services || !data.brands || !data.portfolio) {
      return res.status(400).json({ error: 'Struktur konten tidak lengkap' });
    }
    writeContent(data);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Gagal menyimpan konten: ' + e.message });
  }
});

// POST /api/admin/favicon
app.post('/api/admin/favicon', requireAuth, uploadFavicon.single('favicon'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan' });
  const ext  = path.extname(req.file.filename).toLowerCase();
  const url  = `/public/favicon${ext}`;
  res.json({ success: true, url });
});

// POST /api/admin/photo — upload about photo
app.post('/api/admin/photo', requireAuth, uploadPhoto.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan' });
  const ext = path.extname(req.file.filename).toLowerCase();
  const url = `/public/photo${ext}`;
  res.json({ success: true, url });
});

// GET /api/admin/photo-url — cek foto mana yang aktif
app.get('/api/admin/photo-url', requireAuth, (req, res) => {
  const exts = ['.jpg', '.jpeg', '.png', '.webp'];
  for (const ext of exts) {
    if (fs.existsSync(path.join(UPLOADS_DIR, 'photo' + ext))) {
      return res.json({ url: `/public/photo${ext}` });
    }
  }
  res.json({ url: null });
});

// POST /api/admin/portfolio-thumb/:id — upload thumbnail per portfolio item
app.post('/api/admin/portfolio-thumb/:id', requireAuth, uploadThumb.single('thumb'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan' });
  const id  = req.params.id;
  const ext = path.extname(req.file.filename).toLowerCase();
  const url = `/public/thumbs/thumb-${id}${ext}`;
  res.json({ success: true, url });
});

// GET /api/photo-url — public: dipakai index.html untuk tahu path foto
app.get('/api/photo-url', (req, res) => {
  const exts = ['.jpg', '.jpeg', '.png', '.webp'];
  for (const ext of exts) {
    if (fs.existsSync(path.join(UPLOADS_DIR, 'photo' + ext))) {
      return res.json({ url: `/public/photo${ext}` });
    }
  }
  res.json({ url: null });
});

// GET /api/admin/submissions
app.get('/api/admin/submissions', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM submissions ORDER BY submitted_at DESC').all();
  res.json(rows);
});

// DELETE /api/admin/submissions/:id
app.delete('/api/admin/submissions/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'ID tidak valid' });
  db.prepare('DELETE FROM submissions WHERE id = ?').run(id);
  res.json({ success: true });
});

// ─────────────────────────────────────────────
//  Static Pages
// ─────────────────────────────────────────────

// Admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(ADMIN_DIR, 'index.html'));
});
app.get('/admin/dashboard', (req, res) => {
  res.sendFile(path.join(ADMIN_DIR, 'dashboard.html'));
});

// Serve index.html for all other routes (SPA fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(ROOT, 'index.html'));
});

// ─────────────────────────────────────────────
//  Start
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✦ Sendhy Portfolio berjalan di http://localhost:${PORT}`);
  console.log(`✦ Admin CMS: http://localhost:${PORT}/admin`);
  console.log(`✦ Tekan Ctrl+C untuk stop\n`);
});
