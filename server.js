const express = require('express');
const cors = require('cors');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lunch-wheel-secret-key-george-2026';
const DB_PATH = path.join(__dirname, 'data.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;

async function initDb() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS menus (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
      items TEXT NOT NULL DEFAULT '[]',
      colors TEXT NOT NULL DEFAULT '[]',
      emojis TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      item TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    );
  `);
  saveDb();
}

function saveDb() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Auto-save every 30 seconds
setInterval(saveDb, 30000);

function ensureMenu(userId) {
  const menu = db.exec('SELECT id FROM menus WHERE user_id = ' + userId);
  if (menu.length === 0) {
    db.run('INSERT INTO menus (user_id, items, colors, emojis) VALUES (?, ?, ?, ?)',
      [userId, '["麻辣烫","牛肉面","轻食沙拉","日料定食","酸菜鱼","黄焖鸡","螺蛳粉","广式茶点"]',
       '["#FF6B6B","#4ECDC4","#FFB347","#5B86E5","#A68CDE","#F7DC6F","#82CCDD","#E56B9D"]',
       '["🥟","🍜","🥗","🍱","🐟","🍗","🍣","🥩"]']);
    saveDb();
  }
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: '请先登录' });
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: '登录已失效，请重新登录' });
  }
}

// Helper: run query returning array of objects
function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) { rows.push(stmt.getAsObject()); }
  stmt.free();
  return rows;
}

function queryOne(sql, params = []) {
  const rows = queryAll(sql, params);
  return rows.length > 0 ? rows[0] : null;
}

function run(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

// Auth
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: '用户名长度 2-20 个字符' });
  if (password.length < 4) return res.status(400).json({ error: '密码至少 4 位' });

  const existing = queryOne('SELECT id FROM users WHERE username = ?', [username]);
  if (existing) return res.status(409).json({ error: '用户名已存在' });

  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
  const user = queryOne('SELECT id FROM users WHERE username = ?', [username]);
  ensureMenu(user.id);

  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '100y' });
  res.json({ token, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });

  const user = queryOne('SELECT * FROM users WHERE username = ?', [username]);
  if (!user) return res.status(401).json({ error: '用户名或密码错误' });
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  ensureMenu(user.id);
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '100y' });
  res.json({ token, username });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ username: req.user.username });
});

// Menu
app.get('/api/menu', auth, (req, res) => {
  ensureMenu(req.user.id);
  const menu = queryOne('SELECT items, colors, emojis FROM menus WHERE user_id = ?', [req.user.id]);
  res.json({
    items: JSON.parse(menu.items),
    colors: JSON.parse(menu.colors),
    emojis: JSON.parse(menu.emojis)
  });
});

app.put('/api/menu', auth, (req, res) => {
  const { items, colors, emojis } = req.body;
  if (!items || items.length < 2) return res.status(400).json({ error: '至少需要 2 个菜品' });
  run('UPDATE menus SET items = ?, colors = ?, emojis = ? WHERE user_id = ?',
    [JSON.stringify(items), JSON.stringify(colors || []), JSON.stringify(emojis || []), req.user.id]);
  res.json({ ok: true });
});

// History
app.get('/api/history', auth, (req, res) => {
  const rows = queryAll('SELECT item, created_at FROM history WHERE user_id = ? ORDER BY id DESC LIMIT 50', [req.user.id]);
  res.json(rows);
});

app.post('/api/history', auth, (req, res) => {
  const { item } = req.body;
  if (!item) return res.status(400).json({ error: '缺少菜品名称' });
  run('INSERT INTO history (user_id, item) VALUES (?, ?)', [req.user.id, item]);
  res.json({ ok: true });
});

app.delete('/api/history', auth, (req, res) => {
  run('DELETE FROM history WHERE user_id = ?', [req.user.id]);
  res.json({ ok: true });
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log('🍽️ Lunch Wheel Server running on http://localhost:' + PORT);
  });
});
