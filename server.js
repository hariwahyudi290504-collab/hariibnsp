const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const DB_FILE = path.join(__dirname, 'data.db');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // ensure is_admin column exists (safe to run even if already present)
  db.run("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0", () => {});
  db.run(`CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    link TEXT,
    filename TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS gallery_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.get('SELECT COUNT(*) AS count FROM clients', (err, row) => {
    if (!err && row && row.count === 0) {
      const stmt = db.prepare('INSERT INTO clients (name) VALUES (?)');
      ['Klien A', 'Klien B', 'Klien C', 'Klien D', 'Klien E', 'Klien F'].forEach(name => stmt.run(name));
      stmt.finalize();
    }
  });
});

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_')}`;
      cb(null, safeName);
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 }
});

const app = express();
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));

// Serve admin.html only to authenticated admin users (route declared before static files)
app.get('/admin.html', authenticateToken, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.use(express.static(path.join(__dirname)));

// Serve root path to index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';

function getTokenFromRequest(req) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) return m[1];
  const cookieHeader = req.headers.cookie || '';
  const parts = cookieHeader.split(';').map(s => s.trim());
  for (const p of parts) {
    if (p.startsWith('token=')) return p.substring('token='.length);
  }
  return null;
}

function setTokenCookie(res, token, req) {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  res.cookie('token', token, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax',
    maxAge: 2 * 60 * 60 * 1000 // 2 hours
  });
}

function authenticateToken(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).send('Unauthorized');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).send('Invalid token');
  }
}

function requireAdmin(req, res, next) {
  const userId = req.user && req.user.id;
  if (!userId) return res.status(401).send('Unauthorized');
  db.get('SELECT is_admin FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) return res.status(500).send('Server error');
    if (!row || !row.is_admin) return res.status(403).send('Forbidden');
    next();
  });
}

app.post('/api/signup', async (req, res) => {
  const { name, email, password, adminCode } = req.body || {};
  if (!email || !password) return res.status(400).send('Email dan password wajib');
  try {
    const hash = await bcrypt.hash(password, 10);
    const isAdmin = (adminCode && process.env.ADMIN_CODE && adminCode === process.env.ADMIN_CODE) ? 1 : 0;
    db.run('INSERT INTO users (name,email,password_hash,is_admin) VALUES (?,?,?,?)', [name||null, email, hash, isAdmin], function(err) {
      if (err) return res.status(400).send('Email sudah terdaftar');
      // auto-login: buat token dan set HttpOnly cookie
      const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '2h' });
      setTokenCookie(res, token, req);
      res.status(201).json({ id: this.lastID });
    });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/signin', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).send('Email dan password wajib');
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(400).send('Email atau password salah');
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).send('Email atau password salah');
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
    setTokenCookie(res, token, req);
    res.json({ ok: true });
  });
});

// example protected route
app.get('/api/me', (req, res) => {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).send('Unauthorized');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    db.get('SELECT id,name,email,created_at,is_admin FROM users WHERE id = ?', [payload.id], (err, user) => {
      if (err || !user) return res.status(404).send('User not found');
      res.json(user);
    });
  } catch (e) {
    res.status(401).send('Invalid token');
  }
});

app.get('/api/admin/uploads', authenticateToken, (req, res) => {
  db.all('SELECT id, title, link, filename, created_at FROM uploads ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

app.post('/api/admin/uploads', authenticateToken, upload.single('file'), (req, res) => {
  const { title, link } = req.body || {};
  if (!title) return res.status(400).send('Judul wajib diisi');
  const filename = req.file ? req.file.filename : null;
  db.run('INSERT INTO uploads (title, link, filename) VALUES (?,?,?)', [title, link || null, filename], function(err) {
    if (err) return res.status(500).send('Server error');
    res.status(201).json({ id: this.lastID, title, link, filename });
  });
});

app.get('/api/gallery', (req, res) => {
  db.all('SELECT id, title, filename, created_at FROM gallery_images ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

app.post('/api/admin/gallery', authenticateToken, upload.fields([{ name: 'files', maxCount: 10 }, { name: 'file', maxCount: 10 }]), (req, res) => {
  const { title } = req.body || {};
  if (!title) return res.status(400).send('Judul wajib diisi');
  let files = [];
  if (req.files) {
    if (Array.isArray(req.files)) {
      files = req.files;
    } else {
      // req.files when using fields() is an object: { files:[...], file:[...] }
      Object.keys(req.files).forEach(k => {
        if (Array.isArray(req.files[k])) files.push(...req.files[k]);
      });
    }
  }
  // Multer single() would populate req.file — include it for compatibility
  if (req.file) files.push(req.file);
  if (!files.length) return res.status(400).send('File foto wajib diunggah');
  const stmt = db.prepare('INSERT INTO gallery_images (title, filename) VALUES (?,?)');
  files.forEach(file => stmt.run(title, file.filename));
  stmt.finalize(err => {
    if (err) return res.status(500).send('Server error');
    res.status(201).json({ uploaded: files.length, files: files.map(f => ({ title, filename: f.filename })) });
  });
});

app.delete('/api/admin/gallery/:id', authenticateToken, (req, res) => {
  const id = Number(req.params.id);
  db.get('SELECT filename FROM gallery_images WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).send('Server error');
    if (!row) return res.status(404).send('Image not found');
    const filePath = path.join(UPLOAD_DIR, row.filename);
    fs.unlink(filePath, (e) => {
      // ignore unlink errors (file may not exist)
    });
    db.run('DELETE FROM gallery_images WHERE id = ?', [id], function(err2) {
      if (err2) return res.status(500).send('Server error');
      res.json({ ok: true });
    });
  });
});

app.get('/api/clients', (req, res) => {
  db.all('SELECT id, name FROM clients ORDER BY id ASC', [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

app.post('/api/admin/clients', authenticateToken, (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).send('Nama klien wajib diisi');
  db.run('INSERT INTO clients (name) VALUES (?)', [name], function(err) {
    if (err) return res.status(500).send('Server error');
    res.status(201).json({ id: this.lastID, name });
  });
});

app.patch('/api/admin/clients/:id', authenticateToken, (req, res) => {
  const { name } = req.body || {};
  const id = Number(req.params.id);
  if (!name) return res.status(400).send('Nama klien wajib diisi');
  db.run('UPDATE clients SET name = ? WHERE id = ?', [name, id], function(err) {
    if (err) return res.status(500).send('Server error');
    if (this.changes === 0) return res.status(404).send('Klien tidak ditemukan');
    res.json({ ok: true });
  });
});

app.delete('/api/admin/clients/:id', authenticateToken, (req, res) => {
  const id = Number(req.params.id);
  db.run('DELETE FROM clients WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).send('Server error');
    if (this.changes === 0) return res.status(404).send('Klien tidak ditemukan');
    res.json({ ok: true });
  });
});

// Logout: clear the token cookie
app.post('/api/logout', (req, res) => {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  res.clearCookie('token', { httpOnly: true, secure: isSecure, sameSite: 'lax' });
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
