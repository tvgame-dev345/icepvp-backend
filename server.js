const express = require('express');
const path = require('path');

// חדש: נטען משתני סביבה וקישור ל-Postgres
const dotenv = require('dotenv');
dotenv.config();

const { Pool } = require('pg');

// קרא חיבור מה-.env: שימוש ב-DATABASE_URL אם קיים, אחרת משתני HOST/USER/PASSWORD/DB/PORT
const connectionString = process.env.DATABASE_URL || undefined;

let poolConfig = {};
if (connectionString) {
  // אם ה-DATABASE_URL מבקש ssl (לדוגמה ?sslmode=require), השבת זמנית את בדיקת ה-TLS
  if (/sslmode=require/i.test(connectionString) || /ssl=true/i.test(connectionString)) {
    // עשה זאת רק כדי לעקוף self-signed certs בסביבות שאינן production
    // (אפשר להסיר או לשפר ל-solution מאובטח יותר בסביבת פרודקשן)
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    poolConfig.ssl = { rejectUnauthorized: false };
  }

  poolConfig.connectionString = connectionString;
} else {
  poolConfig = {
    host: process.env.PGHOST,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    port: process.env.PGPORT ? parseInt(process.env.PGPORT, 10) : undefined,
    ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : false
  };
}

const cors = require('cors');

const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = ['https://icepvp.xyz', 'http://localhost:3000'];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
};

const pool = new Pool(poolConfig);

const app = express();
const PORT = 3064;

// JSON body parsing needed for API
app.use(express.json());

// הגדרת תיקיית קבצים סטטיים כדי לשרת CSS, JS ותמונות
app.use(express.static(path.join(__dirname, 'pages')));

// נתיב /news שמגיש את index.html
app.get('/news', (req, res) => {
  const filePath = path.join(__dirname, 'pages', 'news', 'index.html');
  res.sendFile(filePath, (err) => {
    if (err) {
      console.error('Error sending file:', err);
      res.status(500).send('Internal Server Error');
    }
  });
});

// יצירת טבלת news אם לא קיימת
async function ensureTable() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS news (
        id integer PRIMARY KEY,
        text text NOT NULL
      )
    `);
    
    // יצירת טבלת reports
    await client.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        reporting_player_uuid VARCHAR(36) NOT NULL,
        reported_player_uuid VARCHAR(36) NOT NULL,
        reason VARCHAR(255) NOT NULL,
        description TEXT,
        server VARCHAR(100) NOT NULL,
        timestamp TIMESTAMP NOT NULL,
        canceled BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // יצירת טבלת categories
    await client.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        parent_id UUID REFERENCES categories(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // יצירת טבלת packages (עם פקודות כשדות טקסט)
    await client.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        short_description TEXT,
        markdown_description TEXT,
        price DECIMAL(10,2) NOT NULL,
        payment_type VARCHAR(20) CHECK (payment_type IN ('one-time', 'subscription')) NOT NULL,
        subscription_interval INTEGER,
        category_id UUID REFERENCES categories(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // הוספת עמודות פקודות אם הן לא קיימות
    const commandColumns = [
      'initial_command',
      'renewal_command', 
      'expiration_command',
      'refund_command',
      'chargeback_command'
    ];

    for (const column of commandColumns) {
      try {
        await client.query(`ALTER TABLE packages ADD COLUMN IF NOT EXISTS ${column} TEXT`);
      } catch (err) {
        // אם העמודה כבר קיימת, תמשיך
        if (err.code !== '42701') {
          throw err;
        }
      }
    }

    // יצירת טבלת orders
    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        package_id UUID REFERENCES packages(id) ON DELETE SET NULL,
        user_id VARCHAR(255) NOT NULL,
        paypal_order_id VARCHAR(255),
        paypal_subscription_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        amount DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Update existing foreign key constraint and remove NOT NULL constraint
    try {
      await client.query(`
        ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_package_id_fkey
      `);
      await client.query(`
        ALTER TABLE orders ADD CONSTRAINT orders_package_id_fkey 
        FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE SET NULL
      `);
      // Remove NOT NULL constraint from package_id
      await client.query(`
        ALTER TABLE orders ALTER COLUMN package_id DROP NOT NULL
      `);
    } catch (err) {
      // Ignore if constraint doesn't exist or can't be modified
      console.log('Note: Could not update orders constraints');
    }

    // יצירת טבלת staff
    await client.query(`
      CREATE TABLE IF NOT EXISTS staff (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        minecraft_name VARCHAR(255) NOT NULL,
        rank VARCHAR(255) NOT NULL,
        description TEXT,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // טבלת פקודות פר חבילה (ריבוי פקודות לפי סוג)
    await client.query(`
      CREATE TABLE IF NOT EXISTS package_commands (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        package_id UUID NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
        type VARCHAR(20) NOT NULL CHECK (type IN ('initial','renewal','expiration','refund','chargeback')),
        command TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_package_commands_package_id ON package_commands(package_id)
    `);
  } finally {
    client.release();
  }
}

// Handle preflight for all API routes FIRST
app.options('/api/*', cors(corsOptions));

// POST /api/news/create-new
// body JSON: { "text": "..." }
app.post('/api/news/create-new', cors(corsOptions), async (req, res) => {
  const { text } = req.body || {};
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Invalid body: text is required' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // חשב id חדש (אם אין - מתחיל ב-1)
    const { rows } = await client.query('SELECT COALESCE(MAX(id), 0) AS maxid FROM news');
    const nextId = (rows[0].maxid || 0) + 1;

    await client.query('INSERT INTO news (id, text) VALUES ($1, $2)', [nextId, text]);

    await client.query('COMMIT');
    res.status(201).json({ id: nextId, text });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// POST /api/news/delete-new
// body JSON: { "id": 3 }
app.post('/api/news/delete-new', cors(corsOptions), async (req, res) => {
  const { id } = req.body || {};
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Invalid body: id must be a positive integer' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // מחק את השורה
    const del = await client.query('DELETE FROM news WHERE id = $1', [id]);
    if (del.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Not found' });
    }

    // סדר מחדש את ה-ids כך שיתחילו מ-1 לפי סדר עולה
    // שיטה: העתק לספסיק טבלה זמנית עם row_number ואז החלף את התוכן
    await client.query(`
      CREATE TEMP TABLE tmp_news (id integer, text text) ON COMMIT DROP;
    `);
    await client.query(`
      INSERT INTO tmp_news (id, text)
      SELECT row_number() OVER (ORDER BY id) AS id, text
      FROM news
      ORDER BY id
    `);
    await client.query('TRUNCATE TABLE news');
    await client.query('INSERT INTO news (id, text) SELECT id, text FROM tmp_news');

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// GET /api/news/list
app.get('/api/news/list', cors(corsOptions), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, text FROM news ORDER BY id');
    res.json({ news: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// helper: use global fetch if available, otherwise try to require node-fetch
async function _fetch(url, opts) {
  if (typeof fetch === 'function') {
    return fetch(url, opts);
  }
  try {
    // dynamic require in case node-fetch is installed
    // eslint-disable-next-line global-require
    const nodeFetch = require('node-fetch');
    return nodeFetch(url, opts);
  } catch (e) {
    throw new Error('Fetch is not available in this runtime and node-fetch is not installed.');
  }
}

// NEW: build headers/body to forward to upstream (exclude hop-by-hop and host)
function buildForwardOptions(req) {
  const hopByHop = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade']);
  const headers = {};
  Object.entries(req.headers || {}).forEach(([k, v]) => {
    const lk = k.toLowerCase();
    if (lk === 'host') return;
    if (hopByHop.has(lk)) return;
    // don't forward content-length; fetch will set it
    if (lk === 'content-length') return;
    headers[k] = v;
  });

  const opts = {
    method: req.method || 'GET',
    headers
  };

  // forward JSON body if present (express.json() parsed it)
  if (req.body && Object.keys(req.body).length > 0 && /^application\/json/i.test(req.get('content-type') || '')) {
    opts.body = JSON.stringify(req.body);
    // ensure content-type is set
    opts.headers['content-type'] = req.get('content-type') || 'application/json';
  }

  return opts;
}

// helper to proxy response back to client (preserve status, headers, body)
async function proxyResponse(res, upstreamResponse) {
  try {
    // copy status
    res.status(upstreamResponse.status);

    // copy headers, excluding hop-by-hop
    const hopByHop = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade']);
    upstreamResponse.headers.forEach((value, name) => {
      if (!hopByHop.has(name.toLowerCase())) {
        res.setHeader(name, value);
      }
    });

    // send body
    const buf = await upstreamResponse.arrayBuffer();
    return res.send(Buffer.from(buf));
  } catch (err) {
    console.error('Error proxying response:', err);
    return res.status(500).send('Proxy error');
  }
}

// GET /api/verifyme/verify?player=<name>
// forwards to: GET MCWEBAPI_URL/api/verifyme/verify?player=...&access-token=...&server=...
app.post('/api/verifyme/verify', cors(corsOptions), async (req, res) => {
  const player = (req.query && req.query.player) || '';
  const server = (req.body && req.body.server) || 'lobby';
  
  if (!player || typeof player !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid player query parameter' });
  }
  const base = process.env.MCWEBAPI_URL || 'http://mc.hfa.tv-hosting.co.il:4023';
  const token = process.env.MCWEBAPI_TOKEN;
  if (!token) {
    return res.status(500).json({ error: 'MCWEBAPI_TOKEN not configured' });
  }

  try {
    const target = new URL('/api/verifyme/verify', base);
    target.searchParams.set('player', player);
    target.searchParams.set('access-token', token);
    target.searchParams.set('server', server);

    console.log('[MCWEBAPI] Sending verify request:');
    console.log('  URL:', target.toString());
    console.log('  Method: GET');

    const opts = buildForwardOptions(req);
    // ensure upstream is GET (prevents 405)
    opts.method = 'GET';
    delete opts.body;

    console.log('  Headers:', opts.headers);

    const upstream = await _fetch(target.toString(), opts);
    
    console.log('[MCWEBAPI] Verify response:');
    console.log('  Status:', upstream.status);
    console.log('  StatusText:', upstream.statusText);

    return proxyResponse(res, upstream);
  } catch (err) {
    console.error('[MCWEBAPI] Error calling verify endpoint:', err);
    return res.status(502).json({ error: 'Upstream request failed' });
  }
});

// GET /api/verifyme/check?player=<name>
// forwards to: GET MCWEBAPI_URL/api/verifyme/verification-check?player=...&access-token=...&server=...
app.get('/api/verifyme/check', cors(corsOptions), async (req, res) => {
  const player = (req.query && req.query.player) || '';
  const server = (req.query && req.query.server) || 'lobby';
  
  if (!player || typeof player !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid player query parameter' });
  }
  const base = process.env.MCWEBAPI_URL || 'http://mc.hfa.tv-hosting.co.il:4023';
  const token = process.env.MCWEBAPI_TOKEN;
  if (!token) {
    return res.status(500).json({ error: 'MCWEBAPI_TOKEN not configured' });
  }

  try {
    const target = new URL('/api/verifyme/verification-check', base);
    target.searchParams.set('player', player);
    target.searchParams.set('access-token', token);
    target.searchParams.set('server', server);

    console.log('[MCWEBAPI] Sending verification check request:');
    console.log('  URL:', target.toString());
    console.log('  Method: GET');

    const opts = buildForwardOptions(req);
    // ensure upstream is GET (prevents 405)
    opts.method = 'GET';
    delete opts.body;

    console.log('  Headers:', opts.headers);

    const upstream = await _fetch(target.toString(), opts);
    
    console.log('[MCWEBAPI] Verification check response:');
    console.log('  Status:', upstream.status);
    console.log('  StatusText:', upstream.statusText);

    return proxyResponse(res, upstream);
  } catch (err) {
    console.error('[MCWEBAPI] Error calling verification-check endpoint:', err);
    return res.status(502).json({ error: 'Upstream request failed' });
  }
});

// Helper function to send commands to MCWEBAPI
async function sendMCCommand(command, server = 'lobby') {
  const base = process.env.MCWEBAPI_URL || 'http://mc.hfa.tv-hosting.co.il:4023';
  const accessToken = process.env.MCWEBAPI_TOKEN;
  
  if (!accessToken) {
    throw new Error('MCWEBAPI_TOKEN not configured');
  }

  // Build URL with server parameter in query string
  const url = `${base}/api/run-command?server=${encodeURIComponent(server)}`;
  
  // Prepare POST parameters
  const params = new URLSearchParams();
  params.append("access-token", accessToken);
  params.append("command", command);
  
  console.log('[MCWEBAPI] Sending command request:');
  console.log('  URL:', url);
  console.log('  Method: POST');
  console.log('  Headers: Content-Type: application/x-www-form-urlencoded');
  console.log('  Body (URLSearchParams):');
  console.log('    access-token:', accessToken ? '[HIDDEN]' : 'null');
  console.log('    command:', command);
  console.log('  Server (in URL):', server);

  try {
    const response = await _fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString()
    });

    console.log('[MCWEBAPI] Command response:');
    console.log('  Status:', response.status);
    console.log('  StatusText:', response.statusText);

    const responseText = await response.text();
    console.log('  Response body:', responseText);

    return responseText;
  } catch (err) {
    console.error('[MCWEBAPI] Command request failed:', err);
    throw new Error(`Failed to send command: ${err.message}`);
  }
}

// Replace placeholders in any command
function substitutePlaceholders(cmd, player) {
  return String(cmd).replace(/{player}/g, player || '');
}

// Execute all package commands of a given type (initial, refund, renewal, expiration, chargeback)
async function executePackageCommands(packageId, type, player, server = 'lobby') {
  console.log(`[PACKAGE COMMANDS] Executing commands for package ${packageId}, type: ${type}, player: ${player}, server: ${server}`);
  
  const results = [];
  const { rows } = await pool.query(
    `SELECT command, sort_order FROM package_commands
     WHERE package_id = $1 AND type = $2
     ORDER BY sort_order ASC, created_at ASC`,
    [packageId, type]
  );

  console.log(`[PACKAGE COMMANDS] Found ${rows.length} commands to execute`);

  for (const row of rows) {
    const finalCmd = substitutePlaceholders(row.command, player);
    console.log(`[PACKAGE COMMANDS] Executing command: ${finalCmd} on server: ${server}`);
    
    try {
      const resp = await sendMCCommand(finalCmd, server);
      results.push({ ok: true, command: finalCmd, sortOrder: row.sort_order, response: resp });
      console.log(`[PACKAGE COMMANDS] Command executed successfully: ${finalCmd}`);
    } catch (e) {
      console.error(`[PACKAGE COMMANDS] Command failed: ${finalCmd}, error: ${e.message}`);
      results.push({ ok: false, command: finalCmd, sortOrder: row.sort_order, error: e.message });
    }
  }

  console.log(`[PACKAGE COMMANDS] Completed executing ${results.length} commands`);
  return { count: rows.length, results };
}

// POST /api/player/reportpro/new-report
app.post('/api/player/reportpro/new-report', cors(corsOptions), async (req, res) => {
  const { reportingPlayerUUID, reportedPlayerUUID, reason, description, server, timestamp } = req.body || {};
  
  if (!reportingPlayerUUID || !reportedPlayerUUID || !reason || !server || !timestamp) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(
      'INSERT INTO reports (reporting_player_uuid, reported_player_uuid, reason, description, server, timestamp) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [reportingPlayerUUID, reportedPlayerUUID, reason, description, server, timestamp]
    );
    
    res.status(201).json({ id: result.rows[0].id, message: 'Report created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// GET /api/player/reportpro/list
app.get('/api/player/reportpro/list', cors(corsOptions), async (req, res) => {
  const { player } = req.query;
  
  if (!player) {
    return res.status(400).json({ error: 'Player UUID required' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM reports WHERE reporting_player_uuid = $1 ORDER BY created_at DESC',
      [player]
    );
    res.json({ reports: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// DELETE /api/player/reportpro/cancel-report
app.delete('/api/player/reportpro/cancel-report', cors(corsOptions), async (req, res) => {
  const { reportId } = req.body || {};
  
  if (!reportId) {
    return res.status(400).json({ error: 'Report ID required' });
  }

  try {
    const result = await pool.query(
      'UPDATE reports SET canceled = TRUE WHERE id = $1',
      [reportId]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    res.json({ message: 'Report canceled successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// GET /api/player/reportpro/report-info
app.get('/api/player/reportpro/report-info', cors(corsOptions), async (req, res) => {
  const { id } = req.query;
  
  if (!id) {
    return res.status(400).json({ error: 'Report ID required' });
  }

  try {
    const { rows } = await pool.query('SELECT * FROM reports WHERE id = $1', [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    res.json({ report: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// GET /api/staff/reportpro/list
app.get('/api/staff/reportpro/list', cors(corsOptions), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM reports ORDER BY created_at DESC');
    res.json({ reports: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// POST /api/staff/reportpro/ban-player
app.post('/api/staff/reportpro/ban-player', cors(corsOptions), async (req, res) => {
  const { player, reportId, reason, time, server } = req.body || {};
  
  if (!player || !reason || !time) {
    return res.status(400).json({ error: 'Player, reason and time are required' });
  }

  try {
    const command = `ban ${player} ${time} ${reason}`;
    const result = await sendMCCommand(command, server || 'lobby');
    
    res.json({ message: 'Ban command sent successfully', response: result });
  } catch (err) {
    console.error('Error sending ban command:', err);
    res.status(502).json({ error: 'Failed to send ban command' });
  }
});

// POST /api/staff/reportpro/unban
app.post('/api/staff/reportpro/unban', cors(corsOptions), async (req, res) => {
  const { player, reportId, server } = req.body || {};
  
  if (!player) {
    return res.status(400).json({ error: 'Player is required' });
  }

  try {
    const command = `unban ${player}`;
    const result = await sendMCCommand(command, server || 'lobby');
    
    res.json({ message: 'Unban command sent successfully', response: result });
  } catch (err) {
    console.error('Error sending unban command:', err);
    res.status(502).json({ error: 'Failed to send unban command' });
  }
});

// CATEGORIES CRUD
// GET /api/categories
app.get('/api/categories', cors(corsOptions), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM categories ORDER BY name');
    res.json({ categories: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// POST /api/categories
app.post('/api/categories', cors(corsOptions), async (req, res) => {
  const { name, parentId } = req.body || {};
  
  if (!name) {
    return res.status(400).json({ error: 'Name is required' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO categories (name, parent_id) VALUES ($1, $2) RETURNING *',
      [name, parentId || null]
    );
    
    res.status(201).json({ category: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// PUT /api/categories/:id
app.put('/api/categories/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;
  const { name, parentId } = req.body || {};
  
  if (!name) {
    return res.status(400).json({ error: 'Name is required' });
  }

  try {
    const result = await pool.query(
      'UPDATE categories SET name = $1, parent_id = $2 WHERE id = $3 RETURNING *',
      [name, parentId || null, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    res.json({ category: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// DELETE /api/categories/:id
app.delete('/api/categories/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM categories WHERE id = $1', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    res.json({ message: 'Category deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// PACKAGES CRUD (עודכן)
// GET /api/packages
app.get('/api/packages', cors(corsOptions), async (req, res) => {
  try {
    const { rows: packageRows } = await pool.query(`
      SELECT p.*, c.name as category_name 
      FROM packages p 
      LEFT JOIN categories c ON p.category_id = c.id 
      ORDER BY p.name
    `);

    const ids = packageRows.map(p => p.id);
    let commandsByPkg = {};
    if (ids.length > 0) {
      const { rows: cmdRows } = await pool.query(`
        SELECT id, package_id, type, command, sort_order
        FROM package_commands
        WHERE package_id = ANY($1::uuid[])
        ORDER BY sort_order ASC, created_at ASC
      `, [ids]);
      for (const r of cmdRows) {
        if (!commandsByPkg[r.package_id]) commandsByPkg[r.package_id] = [];
        commandsByPkg[r.package_id].push({
          id: r.id,
          type: r.type,
          command: r.command,
          sortOrder: r.sort_order
        });
      }
    }

    const packages = packageRows.map(p => ({
      ...p,
      commands: commandsByPkg[p.id] || []
    }));

    res.json({ packages });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// POST /api/packages - תומך במערך פקודות
app.post('/api/packages', cors(corsOptions), async (req, res) => {
  const { 
    name, shortDescription, markdownDescription, price, paymentType, 
    subscriptionInterval, categoryId, commands 
  } = req.body || {};
  
  if (!name || !price || !paymentType) {
    return res.status(400).json({ error: 'Name, price, and paymentType are required' });
  }

  const allowedTypes = new Set(['initial','renewal','expiration','refund','chargeback']);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // שים לב: לא מאחסנים יותר פקודות בעמודות הטבלה packages
    const result = await client.query(`
      INSERT INTO packages (
        name, short_description, markdown_description, price, payment_type,
        subscription_interval, category_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *
    `, [
      name, shortDescription, markdownDescription, price, paymentType,
      subscriptionInterval || null, categoryId || null
    ]);

    const pkg = result.rows[0];

    // הוספת פקודות אם נשלחו
    let insertedCommands = [];
    if (Array.isArray(commands)) {
      let sort = 1;
      for (const item of commands) {
        if (!item || typeof item.command !== 'string' || !allowedTypes.has(item.type)) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Invalid command item. Must include type (initial|renewal|expiration|refund|chargeback) and command (string)' });
        }
        const sortOrder = Number.isInteger(item.sortOrder) ? item.sortOrder : sort++;
        const { rows: cmdIns } = await client.query(`
          INSERT INTO package_commands (package_id, type, command, sort_order)
          VALUES ($1, $2, $3, $4) RETURNING id, type, command, sort_order
        `, [pkg.id, item.type, item.command, sortOrder]);
        insertedCommands.push({
          id: cmdIns[0].id,
          type: cmdIns[0].type,
          command: cmdIns[0].command,
          sortOrder: cmdIns[0].sort_order
        });
      }
    }

    await client.query('COMMIT');
    res.status(201).json({ package: { ...pkg, commands: insertedCommands } });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// PUT /api/packages/:id - תומך בהחלפת כל הפקודות (אם נשלח commands)
app.put('/api/packages/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;
  const { 
    name, shortDescription, markdownDescription, price, paymentType, 
    subscriptionInterval, categoryId, commands
  } = req.body || {};
  
  if (!name || !price || !paymentType) {
    return res.status(400).json({ error: 'Name, price, and paymentType are required' });
  }

  const allowedTypes = new Set(['initial','renewal','expiration','refund','chargeback']);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const result = await client.query(`
      UPDATE packages SET 
        name = $1, short_description = $2, markdown_description = $3, price = $4, 
        payment_type = $5, subscription_interval = $6, category_id = $7
      WHERE id = $8 RETURNING *
    `, [
      name, shortDescription, markdownDescription, price, paymentType,
      subscriptionInterval || null, categoryId || null, id
    ]);
    
    if (result.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Package not found' });
    }

    // אם נשלח commands - מחליפים את כל הפקודות של החבילה
    let newCommands = undefined;
    if (Array.isArray(commands)) {
      // מחיקה קיימות
      await client.query('DELETE FROM package_commands WHERE package_id = $1', [id]);

      // הוספה מחדש לפי הסדר
      newCommands = [];
      let sort = 1;
      for (const item of commands) {
        if (!item || typeof item.command !== 'string' || !allowedTypes.has(item.type)) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Invalid command item. Must include type (initial|renewal|expiration|refund|chargeback) and command (string)' });
        }
        const sortOrder = Number.isInteger(item.sortOrder) ? item.sortOrder : sort++;
        const { rows: cmdIns } = await client.query(`
          INSERT INTO package_commands (package_id, type, command, sort_order)
          VALUES ($1, $2, $3, $4) RETURNING id, type, command, sort_order
        `, [id, item.type, item.command, sortOrder]);
        newCommands.push({
          id: cmdIns[0].id,
          type: cmdIns[0].type,
          command: cmdIns[0].command,
          sortOrder: cmdIns[0].sort_order
        });
      }
    }

    await client.query('COMMIT');

    // טען את הפקודות אם לא נשלחו (להחזרת המצב העדכני)
    if (!Array.isArray(commands)) {
      const { rows: existing } = await pool.query(`
        SELECT id, type, command, sort_order FROM package_commands
        WHERE package_id = $1 ORDER BY sort_order ASC, created_at ASC
      `, [id]);
      newCommands = existing.map(r => ({ id: r.id, type: r.type, command: r.command, sortOrder: r.sort_order }));
    }

    res.json({ package: { ...result.rows[0], commands: newCommands } });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// DELETE /api/packages/:id
app.delete('/api/packages/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;

  try {
    // Delete package (package_commands are removed via ON DELETE CASCADE)
    const result = await pool.query('DELETE FROM packages WHERE id = $1', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Package not found' });
    }
    
    res.json({ message: 'Package deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// GET /api/shop
app.get('/api/shop', cors(corsOptions), async (req, res) => {
  try {
    // Get all categories and packages
    const categoriesResult = await pool.query('SELECT * FROM categories ORDER BY name');
    const packagesResult = await pool.query(`
      SELECT id, name, short_description, markdown_description, price, payment_type, category_id 
      FROM packages ORDER BY name
    `);
    
    const categories = categoriesResult.rows;
    const packages = packagesResult.rows;
    
    // Build nested structure
    function buildCategoryTree(parentId = null) {
      return categories
        .filter(cat => cat.parent_id === parentId)
        .map(cat => ({
          id: cat.id,
          name: cat.name,
          parentId: cat.parent_id,
          packages: packages.filter(pkg => pkg.category_id === cat.id),
          subcategories: buildCategoryTree(cat.id)
        }));
    }
    
    res.json({ categories: buildCategoryTree() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Helper function to get PayPal access token
async function getPayPalAccessToken() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
  
  if (!clientId || !clientSecret) {
    throw new Error('PayPal credentials not configured');
  }

  const auth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  
  try {
    const response = await _fetch('https://api-m.sandbox.paypal.com/v1/oauth2/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'grant_type=client_credentials'
    });
    
    const data = await response.json();
    return data.access_token;
  } catch (err) {
    throw new Error(`Failed to get PayPal access token: ${err.message}`);
  }
}

// Helper function to create PayPal billing plan
async function createPayPalBillingPlan(packageData) {
  const accessToken = await getPayPalAccessToken();
  
  // Create product first - use shorter unique ID to avoid length limits
  const shortId = packageData.id.replace(/-/g, '').substring(0, 20); // Remove hyphens and limit length
  const uniqueId = `prod_${shortId}_${Date.now().toString().slice(-6)}`; // Use last 6 digits of timestamp
  
  const productData = {
    id: uniqueId,
    name: packageData.name,
    description: packageData.short_description || packageData.name,
    type: 'SERVICE',
    category: 'SOFTWARE'
  };

  console.log('Creating PayPal product:', productData);

  const productResponse = await _fetch('https://api-m.sandbox.paypal.com/v1/catalogs/products', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'PayPal-Request-Id': `product_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    },
    body: JSON.stringify(productData)
  });

  let productId;
  if (productResponse.ok) {
    const product = await productResponse.json();
    console.log('Product created successfully:', product);
    productId = product.id;
  } else if (productResponse.status === 422 || productResponse.status === 400) {
    // If product creation fails, try with an even shorter random ID
    const errorData = await productResponse.json().catch(() => ({}));
    console.log('Product creation failed, trying alternative approach:', errorData);
    
    // Try with a completely random short ID
    const fallbackId = `prod_${Math.random().toString(36).substr(2, 8)}_${Date.now().toString().slice(-4)}`;
    const fallbackProductData = {
      ...productData,
      id: fallbackId
    };
    
    const fallbackResponse = await _fetch('https://api-m.sandbox.paypal.com/v1/catalogs/products', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': `product_fallback_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      },
      body: JSON.stringify(fallbackProductData)
    });
    
    if (fallbackResponse.ok) {
      const fallbackProduct = await fallbackResponse.json();
      console.log('Fallback product created successfully:', fallbackProduct);
      productId = fallbackProduct.id;
    } else {
      const fallbackErrorData = await fallbackResponse.json().catch(() => ({}));
      console.error('Fallback product creation also failed:', {
        status: fallbackResponse.status,
        statusText: fallbackResponse.statusText,
        error: fallbackErrorData
      });
      throw new Error(`Failed to create PayPal product: ${fallbackResponse.status} ${fallbackResponse.statusText} - ${JSON.stringify(fallbackErrorData)}`);
    }
  } else {
    const errorData = await productResponse.json().catch(() => ({}));
    console.error('PayPal product creation failed:', {
      status: productResponse.status,
      statusText: productResponse.statusText,
      error: errorData
    });
    throw new Error(`Failed to create PayPal product: ${productResponse.status} ${productResponse.statusText} - ${JSON.stringify(errorData)}`);
  }

  // Create billing plan
  const planData = {
    product_id: productId,
    name: `${packageData.name} Subscription`,
    description: packageData.short_description || packageData.name,
    status: 'ACTIVE',
    billing_cycles: [{
      frequency: {
        interval_unit: 'DAY',
        interval_count: packageData.subscription_interval || 30
      },
      tenure_type: 'REGULAR',
      sequence: 1,
      total_cycles: 0, // Infinite
      pricing_scheme: {
        fixed_price: {
          value: packageData.price.toString(),
          currency_code: 'ILS'
        }
      }
    }],
    payment_preferences: {
      auto_bill_outstanding: true,
      setup_fee_failure_action: 'CONTINUE',
      payment_failure_threshold: 3
    }
  };

  console.log('Creating PayPal billing plan:', planData);

  const planResponse = await _fetch('https://api-m.sandbox.paypal.com/v1/billing/plans', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'PayPal-Request-Id': `plan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    },
    body: JSON.stringify(planData)
  });

  if (!planResponse.ok) {
    const error = await planResponse.json().catch(() => ({}));
    console.error('PayPal plan creation failed:', {
      status: planResponse.status,
      statusText: planResponse.statusText,
      error: error
    });
    throw new Error(`Failed to create PayPal plan: ${planResponse.status} ${planResponse.statusText} - ${JSON.stringify(error)}`);
  }

  const plan = await planResponse.json();
  console.log('Billing plan created successfully:', plan);
  return plan;
}

// Helper function for PayPal integration
async function createPayPalOrder(packageData, userId) {
  try {
    const accessToken = await getPayPalAccessToken();
    
    // For subscriptions, create subscription instead of order
    if (packageData.payment_type === 'subscription') {
      // Create billing plan
      const plan = await createPayPalBillingPlan(packageData);
      
      // Create subscription
      const subscriptionData = {
        plan_id: plan.id,
        subscriber: {
          name: {
            given_name: 'Customer',
            surname: userId
          }
        },
        application_context: {
          brand_name: 'IcePVP',
          locale: 'en-US',
          shipping_preference: 'NO_SHIPPING',
          user_action: 'SUBSCRIBE_NOW',
          return_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/payment/success`,
          cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/payment/cancel`
        }
      };

      const response = await _fetch('https://api-m.sandbox.paypal.com/v1/billing/subscriptions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'PayPal-Request-Id': `sub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        },
        body: JSON.stringify(subscriptionData)
      });

      const subscription = await response.json();
      
      if (!response.ok) {
        throw new Error(`PayPal Subscription API error: ${subscription.message || 'Unknown error'}`);
      }

      // Find approval URL
      const approvalUrl = subscription.links.find(link => link.rel === 'approve')?.href;
      
      return { 
        paypalOrderId: subscription.id, 
        approvalUrl: approvalUrl || `https://sandbox.paypal.com/webapps/billing/subscriptions/approve?subscription_id=${subscription.id}`,
        isSubscription: true
      };
    }
    
    // For one-time payments, create regular order
    const orderData = {
      intent: 'CAPTURE',
      purchase_units: [{
        amount: {
          currency_code: 'ILS',
          value: packageData.price.toString()
        },
        description: packageData.name,
        custom_id: `${packageData.id}_${userId}`
      }],
      application_context: {
        return_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/payment/success`,
        cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/payment/cancel`,
        brand_name: 'IcePVP',
        landing_page: 'BILLING',
        user_action: 'PAY_NOW'
      }
    };

    const response = await _fetch('https://api-m.sandbox.paypal.com/v2/checkout/orders', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      },
      body: JSON.stringify(orderData)
    });

    const order = await response.json();
    
    if (!response.ok) {
      throw new Error(`PayPal API error: ${order.message || 'Unknown error'}`);
    }

    // Find approval URL
    const approvalUrl = order.links.find(link => link.rel === 'approve')?.href;
    
    return { 
      paypalOrderId: order.id, 
      approvalUrl: approvalUrl || `https://sandbox.paypal.com/checkoutnow?token=${order.id}`,
      isSubscription: false
    };
  } catch (err) {
    throw new Error(`Failed to create PayPal order: ${err.message}`);
  }
}

// POST /api/payments/create
app.post('/api/payments/create', cors(corsOptions), async (req, res) => {
  const { packageId, userId, server } = req.body || {};
  
  if (!packageId || !userId) {
    return res.status(400).json({ error: 'packageId and userId are required' });
  }

  console.log(`[PAYMENT CREATE] Creating payment for package: ${packageId}, user: ${userId}, server: ${server || 'lobby'}`);

  const client = await pool.connect();
  try {
    // Get package details
    const packageResult = await pool.query('SELECT * FROM packages WHERE id = $1', [packageId]);
    
    if (packageResult.rows.length === 0) {
      return res.status(404).json({ error: 'Package not found' });
    }
    
    const packageData = packageResult.rows[0];
    console.log(`[PAYMENT CREATE] Package found: ${packageData.name}, type: ${packageData.payment_type}`);
    
    // Create PayPal order or subscription
    const { paypalOrderId, approvalUrl, isSubscription } = await createPayPalOrder(packageData, userId);
    
    // Store order in database with server info
    const insertQuery = isSubscription ? 
      `INSERT INTO orders (package_id, user_id, paypal_subscription_id, amount, status)
       VALUES ($1, $2, $3, $4, 'pending')` :
      `INSERT INTO orders (package_id, user_id, paypal_order_id, amount, status)
       VALUES ($1, $2, $3, $4, 'pending')`;
    
    await pool.query(insertQuery, [packageId, userId, paypalOrderId, packageData.price]);
    
    console.log(`[PAYMENT CREATE] Order created in database with ID: ${paypalOrderId}`);
    
    res.json({ 
      approval_url: approvalUrl, 
      order_id: paypalOrderId, 
      is_subscription: isSubscription,
      server: server || 'lobby'
    });
  } catch (err) {
    console.error('[PAYMENT CREATE] Error:', err);
    res.status(500).json({ error: 'Failed to create payment' });
  } finally {
    client.release();
  }
});

// POST /api/payments/complete
app.post('/api/payments/complete', cors(corsOptions), async (req, res) => {
  const { PayerID, token, subscription_id, server } = req.body || {};
  
  if (!PayerID && !subscription_id) {
    return res.status(400).json({ error: 'PayerID or subscription_id is required' });
  }

  const client = await pool.connect();
  try {
    let order;
    const orderId = subscription_id || token;
    
    // Find order by PayPal order ID or subscription ID
    const orderResult = await client.query(
      'SELECT * FROM orders WHERE paypal_order_id = $1 OR paypal_subscription_id = $1',
      [orderId]
    );
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    order = orderResult.rows[0];
    
    // Check if order is already completed
    if (order.status === 'completed') {
      return res.json({ 
        message: 'Order already processed', 
        order_id: orderId,
        status: 'completed' 
      });
    }

    const accessToken = await getPayPalAccessToken();
    
    // Handle subscription activation
    if (subscription_id) {
      // Get subscription details to verify it's active
      const subResponse = await _fetch(`https://api-m.sandbox.paypal.com/v1/billing/subscriptions/${subscription_id}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      const subscription = await subResponse.json();
      
      if (!subResponse.ok || subscription.status !== 'ACTIVE') {
        return res.status(400).json({ 
          error: 'Subscription activation failed', 
          details: subscription.status || 'Unknown error' 
        });
      }
      
      // Update order status
      await client.query(
        'UPDATE orders SET status = $1 WHERE paypal_subscription_id = $2',
        ['completed', subscription_id]
      );
      
    } else {
      // Handle one-time payment capture
      const captureResponse = await _fetch(`https://api-m.sandbox.paypal.com/v2/checkout/orders/${token}/capture`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      const captureData = await captureResponse.json();
      
      if (!captureResponse.ok || captureData.status !== 'COMPLETED') {
        console.error('PayPal capture failed:', captureData);
        return res.status(400).json({ 
          error: 'Payment capture failed', 
          details: captureData.details || captureData.message 
        });
      }
      
      // Update order status
      await client.query(
        'UPDATE orders SET status = $1 WHERE paypal_order_id = $2',
        ['completed', token]
      );
    }
    
    // Execute all 'initial' commands for this package
    const execSummary = await executePackageCommands(order.package_id, 'initial', order.user_id, server || 'lobby');

    if (execSummary.count > 0) {
      return res.json({
        message: 'Payment completed and commands executed',
        order_id: orderId,
        status: 'completed',
        command_results: execSummary.results
      });
    }

    return res.json({
      message: 'Payment completed successfully',
      order_id: orderId,
      status: 'completed',
      note: 'No commands to execute'
    });

  } catch (err) {
    console.error('Payment completion error:', err);
    res.status(500).json({ error: 'Failed to complete payment' });
  } finally {
    client.release();
  }
});

// POST /api/payments/subscription/complete
app.post('/api/payments/subscription/complete', cors(corsOptions), async (req, res) => {
  const { subscription_id, server } = req.body || {};
  
  if (!subscription_id) {
    return res.status(400).json({ error: 'subscription_id is required' });
  }

  const client = await pool.connect();
  try {
    // Find order by PayPal subscription ID
    const orderResult = await client.query(
      'SELECT * FROM orders WHERE paypal_subscription_id = $1',
      [subscription_id]
    );
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Subscription order not found' });
    }
    
    const order = orderResult.rows[0];
    
    // Check if order is already completed
    if (order.status === 'completed') {
      return res.json({ 
        message: 'Subscription already processed', 
        order_id: subscription_id,
        status: 'completed' 
      });
    }

    const accessToken = await getPayPalAccessToken();
    
    // Get subscription details to verify it's active
    const subResponse = await _fetch(`https://api-m.sandbox.paypal.com/v1/billing/subscriptions/${subscription_id}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const subscription = await subResponse.json();
    
    if (!subResponse.ok || subscription.status !== 'ACTIVE') {
      return res.status(400).json({ 
        error: 'Subscription activation failed', 
        details: subscription.status || 'Unknown error' 
      });
    }
    
    // Update order status
    await client.query(
      'UPDATE orders SET status = $1 WHERE paypal_subscription_id = $2',
      ['completed', subscription_id]
    );
    
    // Execute all 'initial' commands for this package
    const execSummary = await executePackageCommands(order.package_id, 'initial', order.user_id, server || 'lobby');

    if (execSummary.count > 0) {
      return res.json({
        message: 'Subscription completed and commands executed',
        order_id: subscription_id,
        status: 'completed',
        command_results: execSummary.results
      });
    }

    return res.json({
      message: 'Subscription completed successfully',
      order_id: subscription_id,
      status: 'completed',
      note: 'No commands to execute'
    });

  } catch (err) {
    console.error('Subscription completion error:', err);
    res.status(500).json({ error: 'Failed to complete subscription' });
  } finally {
    client.release();
  }
});

// New endpoint to handle PayPal webhook/completion
app.post('/api/payments/paypal-webhook', cors(corsOptions), async (req, res) => {
  const { event_type, resource } = req.body || {};
  console.log(`[PAYPAL WEBHOOK] Received event: ${event_type}`);
  
  try {
    switch (event_type) {
      case 'CHECKOUT.ORDER.APPROVED':
      case 'PAYMENT.CAPTURE.COMPLETED': {
        const orderId = resource.id || resource.supplementary_data?.related_ids?.order_id;
        console.log(`[PAYPAL WEBHOOK] Processing order completion: ${orderId}`);
        
        const orderResult = await pool.query(
          'SELECT * FROM orders WHERE paypal_order_id = $1',
          [orderId]
        );
        if (orderResult.rows.length > 0) {
          const order = orderResult.rows[0];
          console.log(`[PAYPAL WEBHOOK] Order found for user: ${order.user_id}, package: ${order.package_id}`);

          await pool.query(
            'UPDATE orders SET status = $1 WHERE paypal_order_id = $2',
            ['completed', orderId]
          );

          // Execute with default server for webhook events
          await executePackageCommands(order.package_id, 'initial', order.user_id, 'lobby');
        }
        break;
      }

      case 'BILLING.SUBSCRIPTION.ACTIVATED': {
        const subscriptionId = resource.id;
        console.log(`[PAYPAL WEBHOOK] Processing subscription activation: ${subscriptionId}`);
        
        const orderResult = await pool.query(
          'SELECT * FROM orders WHERE paypal_subscription_id = $1',
          [subscriptionId]
        );
        if (orderResult.rows.length > 0) {
          const order = orderResult.rows[0];
          console.log(`[PAYPAL WEBHOOK] Subscription found for user: ${order.user_id}, package: ${order.package_id}`);

          await pool.query(
            'UPDATE orders SET status = $1 WHERE paypal_subscription_id = $2',
            ['completed', subscriptionId]
          );

          await executePackageCommands(order.package_id, 'initial', order.user_id, 'lobby');
        }
        break;
      }

      case 'BILLING.SUBSCRIPTION.PAYMENT.COMPLETED': {
        const subscriptionId = resource.billing_agreement_id;
        console.log(`[PAYPAL WEBHOOK] Processing subscription renewal: ${subscriptionId}`);
        
        const orderResult = await pool.query(
          'SELECT * FROM orders WHERE paypal_subscription_id = $1',
          [subscriptionId]
        );
        if (orderResult.rows.length > 0) {
          const order = orderResult.rows[0];
          console.log(`[PAYPAL WEBHOOK] Executing renewal commands for user: ${order.user_id}`);
          await executePackageCommands(order.package_id, 'renewal', order.user_id, 'lobby');
        }
        break;
      }

      case 'BILLING.SUBSCRIPTION.CANCELLED':
      case 'BILLING.SUBSCRIPTION.EXPIRED': {
        const subscriptionId = resource.id;
        console.log(`[PAYPAL WEBHOOK] Processing subscription expiration: ${subscriptionId}`);
        
        const orderResult = await pool.query(
          'SELECT * FROM orders WHERE paypal_subscription_id = $1',
          [subscriptionId]
        );
        if (orderResult.rows.length > 0) {
          const order = orderResult.rows[0];
          console.log(`[PAYPAL WEBHOOK] Executing expiration commands for user: ${order.user_id}`);
          await executePackageCommands(order.package_id, 'expiration', order.user_id, 'lobby');
        }
        break;
      }

      case 'BILLING.SUBSCRIPTION.PAYMENT.FAILED':
      case 'PAYMENT.CAPTURE.REFUNDED': {
        const refundOrderId = resource.supplementary_data?.related_ids?.order_id || resource.billing_agreement_id;
        console.log(`[PAYPAL WEBHOOK] Processing refund: ${refundOrderId}`);
        
        if (refundOrderId) {
          const refundOrder = await pool.query(
            'SELECT * FROM orders WHERE paypal_order_id = $1 OR paypal_subscription_id = $1',
            [refundOrderId]
          );
          if (refundOrder.rows.length > 0) {
            const order = refundOrder.rows[0];
            console.log(`[PAYPAL WEBHOOK] Executing refund commands for user: ${order.user_id}`);
            await executePackageCommands(order.package_id, 'refund', order.user_id, 'lobby');
          }
        }
        break;
      }

      default:
        console.log(`[PAYPAL WEBHOOK] Unhandled event: ${event_type}`);
        break;
    }
    res.status(200).send('OK');
  } catch (err) {
    console.error('[PAYPAL WEBHOOK] Error processing webhook:', err);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// STAFF MANAGEMENT CRUD
// GET /api/staff
app.get('/api/staff', cors(corsOptions), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM staff ORDER BY sort_order ASC, id ASC');
    res.json({ staff: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// POST /api/staff
app.post('/api/staff', cors(corsOptions), async (req, res) => {
  const { name, minecraftName, rank, description } = req.body || {};
  
  if (!name || !minecraftName || !rank) {
    return res.status(400).json({ error: 'Name, minecraftName, and rank are required' });
  }

  const client = await pool.connect();
  try {
    // Get the highest sort_order to append new staff at the end
    const { rows: maxRows } = await client.query('SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM staff');
    const nextOrder = (maxRows[0].max_order || 0) + 1;

    const result = await client.query(
      'INSERT INTO staff (name, minecraft_name, rank, description, sort_order) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, minecraftName, rank, description, nextOrder]
    );
    
    res.status(201).json({ staff: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// PUT /api/staff/:id
app.put('/api/staff/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;
  const { name, minecraftName, rank, description } = req.body || {};
  
  if (!name || !minecraftName || !rank) {
    return res.status(400).json({ error: 'Name, minecraftName, and rank are required' });
  }

  try {
    const result = await pool.query(
      'UPDATE staff SET name = $1, minecraft_name = $2, rank = $3, description = $4 WHERE id = $5 RETURNING *',
      [name, minecraftName, rank, description, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Staff member not found' });
    }
    
    res.json({ staff: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// DELETE /api/staff/:id
app.delete('/api/staff/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Delete the staff member
    const deleteResult = await client.query('DELETE FROM staff WHERE id = $1 RETURNING sort_order', [id]);
    
    if (deleteResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Staff member not found' });
    }

    const deletedOrder = deleteResult.rows[0].sort_order;

    // Reorder remaining staff members to fill the gap
    await client.query(
      'UPDATE staff SET sort_order = sort_order - 1 WHERE sort_order > $1',
      [deletedOrder]
    );

    await client.query('COMMIT');
    res.json({ message: 'Staff member deleted successfully' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// POST /api/staff/reorder
app.post('/api/staff/reorder', cors(corsOptions), async (req, res) => {
  const { order } = req.body || {};
  
  if (!Array.isArray(order)) {
    return res.status(400).json({ error: 'Order must be an array of objects with id property' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Update sort_order for each staff member based on the new order
    for (let i = 0; i < order.length; i++) {
      const { id } = order[i];
      if (!id) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Each item in order array must have an id property' });
      }

      await client.query(
        'UPDATE staff SET sort_order = $1 WHERE id = $2',
        [i + 1, id]
      );
    }

    await client.query('COMMIT');
    
    // Return updated staff list
    const { rows } = await client.query('SELECT * FROM staff ORDER BY sort_order ASC, id ASC');
    res.json({ staff: rows, message: 'Staff order updated successfully' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// SHOP STATISTICS ENDPOINTS
// GET /api/shop/stats/revenue - Total revenue from shop
app.get('/api/shop/stats/revenue', cors(corsOptions), async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        SUM(amount) as total_revenue,
        COUNT(*) as total_orders,
        AVG(amount) as average_order_value
      FROM orders 
      WHERE status = 'completed'
    `);
    
    const revenue = {
      total_revenue: parseFloat(rows[0].total_revenue || 0),
      total_orders: parseInt(rows[0].total_orders || 0),
      average_order_value: parseFloat(rows[0].average_order_value || 0)
    };
    
    res.json({ revenue });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// GET /api/shop/stats/packages - Package purchase statistics (percentages)
app.get('/api/shop/stats/packages', cors(corsOptions), async (req, res) => {
  try {
    // Get total completed orders
    const totalResult = await pool.query(`
      SELECT COUNT(*) as total 
      FROM orders 
      WHERE status = 'completed'
    `);
    
    const totalOrders = parseInt(totalResult.rows[0].total || 0);
    
    if (totalOrders === 0) {
      return res.json({ 
        package_stats: [],
        total_orders: 0,
        message: 'No completed orders found'
      });
    }
    
    // Get package statistics
    const { rows } = await pool.query(`
      SELECT 
        p.name as package_name,
        p.id as package_id,
        COUNT(o.id) as order_count,
        ROUND((COUNT(o.id)::decimal / $1 * 100), 2) as percentage,
        SUM(o.amount) as total_revenue
      FROM packages p
      LEFT JOIN orders o ON p.id = o.package_id AND o.status = 'completed'
      GROUP BY p.id, p.name
      ORDER BY order_count DESC
      LIMIT 5
    `, [totalOrders]);
    
    const packageStats = rows.map(row => ({
      package_id: row.package_id,
      package_name: row.package_name,
      order_count: parseInt(row.order_count || 0),
      percentage: parseFloat(row.percentage || 0),
      total_revenue: parseFloat(row.total_revenue || 0)
    }));
    
    res.json({ 
      package_stats: packageStats,
      total_orders: totalOrders
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// GET /api/shop/stats/customers - Total unique customers who purchased
app.get('/api/shop/stats/customers', cors(corsOptions), async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        COUNT(DISTINCT user_id) as unique_customers,
        COUNT(*) as total_orders,
        CASE 
          WHEN COUNT(DISTINCT user_id) > 0 
          THEN ROUND(COUNT(*)::decimal / COUNT(DISTINCT user_id), 2)
          ELSE 0 
        END as orders_per_customer
      FROM orders 
      WHERE status = 'completed'
    `);
    
    const customerStats = {
      unique_customers: parseInt(rows[0].unique_customers || 0),
      total_orders: parseInt(rows[0].total_orders || 0),
      orders_per_customer: parseFloat(rows[0].orders_per_customer || 0)
    };
    
    res.json({ customer_stats: customerStats });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// PAYPAL WEBHOOK ENDPOINTS
// POST /api/webhooks/paypal/subscription-cancelled
app.post('/api/webhooks/paypal/subscription-cancelled', cors(corsOptions), async (req, res) => {
  const { subscription_id, server } = req.body || {};
  
  if (!subscription_id) {
    return res.status(400).json({ error: 'subscription_id is required' });
  }

  console.log(`[WEBHOOK CANCEL] Processing subscription cancellation: ${subscription_id}, server: ${server || 'lobby'}`);

  const client = await pool.connect();
  try {
    // Find order by PayPal subscription ID
    const orderResult = await client.query(
      'SELECT * FROM orders WHERE paypal_subscription_id = $1',
      [subscription_id]
    );
    
    if (orderResult.rows.length === 0) {
      console.log(`[WEBHOOK CANCEL] Subscription not found in database: ${subscription_id}`);
      return res.status(404).json({ error: 'Subscription not found' });
    }
    
    const order = orderResult.rows[0];
    console.log(`[WEBHOOK CANCEL] Found subscription for user: ${order.user_id}, package: ${order.package_id}`);
    
    // Update order status to cancelled
    await client.query(
      'UPDATE orders SET status = $1 WHERE paypal_subscription_id = $2',
      ['cancelled', subscription_id]
    );
    
    console.log(`[WEBHOOK CANCEL] Updated order status to cancelled`);
    
    // Execute all 'expiration' commands for this package (cancellation = expiration)
    const execSummary = await executePackageCommands(order.package_id, 'expiration', order.user_id, server || 'lobby');

    console.log(`[WEBHOOK CANCEL] Executed ${execSummary.count} expiration commands`);

    res.json({
      message: 'Subscription cancelled and commands executed',
      subscription_id: subscription_id,
      user_id: order.user_id,
      package_id: order.package_id,
      command_results: execSummary.results,
      total_commands: execSummary.count
    });

  } catch (err) {
    console.error('[WEBHOOK CANCEL] Error processing cancellation:', err);
    res.status(500).json({ error: 'Failed to process subscription cancellation' });
  } finally {
    client.release();
  }
});

// POST /api/webhooks/paypal/subscription-payment
app.post('/api/webhooks/paypal/subscription-payment', cors(corsOptions), async (req, res) => {
  const { subscription_id, server } = req.body || {};
  
  if (!subscription_id) {
    return res.status(400).json({ error: 'subscription_id is required' });
  }

  console.log(`[WEBHOOK PAYMENT] Processing subscription renewal payment: ${subscription_id}, server: ${server || 'lobby'}`);

  const client = await pool.connect();
  try {
    // Find order by PayPal subscription ID
    const orderResult = await client.query(
      'SELECT * FROM orders WHERE paypal_subscription_id = $1',
      [subscription_id]
    );
    
    if (orderResult.rows.length === 0) {
      console.log(`[WEBHOOK PAYMENT] Subscription not found in database: ${subscription_id}`);
      return res.status(404).json({ error: 'Subscription not found' });
    }
    
    const order = orderResult.rows[0];
    console.log(`[WEBHOOK PAYMENT] Found subscription for user: ${order.user_id}, package: ${order.package_id}`);
    
    // Make sure order is in completed status for active subscriptions
    if (order.status !== 'completed') {
      await client.query(
        'UPDATE orders SET status = $1 WHERE paypal_subscription_id = $2',
        ['completed', subscription_id]
      );
      console.log(`[WEBHOOK PAYMENT] Updated order status to completed`);
    }
    
    // Execute all 'renewal' commands for this package
    const execSummary = await executePackageCommands(order.package_id, 'renewal', order.user_id, server || 'lobby');

    console.log(`[WEBHOOK PAYMENT] Executed ${execSummary.count} renewal commands`);

    res.json({
      message: 'Subscription renewal processed and commands executed',
      subscription_id: subscription_id,
      user_id: order.user_id,
      package_id: order.package_id,
      command_results: execSummary.results,
      total_commands: execSummary.count
    });

  } catch (err) {
    console.error('[WEBHOOK PAYMENT] Error processing renewal:', err);
    res.status(500).json({ error: 'Failed to process subscription renewal' });
  } finally {
    client.release();
  }
});

// ADMIN ORDER MANAGEMENT ENDPOINTS

// GET /api/admin/orders/list - Paginated order list with filters
app.get('/api/admin/orders/list', cors(corsOptions), async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;
  const { status, user_id, package_id, sort_by, sort_order } = req.query;

  console.log(`[ADMIN ORDERS] List request - page: ${page}, limit: ${limit}, filters: status=${status}, user_id=${user_id}, package_id=${package_id}`);

  try {
    // Build WHERE clause with filters
    let whereConditions = [];
    let queryParams = [];
    let paramIndex = 1;

    if (status) {
      whereConditions.push(`o.status = $${paramIndex}`);
      queryParams.push(status);
      paramIndex++;
    }

    if (user_id) {
      whereConditions.push(`o.user_id ILIKE $${paramIndex}`);
      queryParams.push(`%${user_id}%`);
      paramIndex++;
    }

    if (package_id) {
      whereConditions.push(`o.package_id = $${paramIndex}`);
      queryParams.push(package_id);
      paramIndex++;
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    // Build ORDER BY clause
    const validSortFields = ['created_at', 'amount', 'status', 'user_id'];
    const sortField = validSortFields.includes(sort_by) ? sort_by : 'created_at';
    const sortDirection = sort_order === 'asc' ? 'ASC' : 'DESC';

    // Get total count for pagination
    const countQuery = `
      SELECT COUNT(*) as total
      FROM orders o
      LEFT JOIN packages p ON o.package_id = p.id
      ${whereClause}
    `;
    
    const countResult = await pool.query(countQuery, queryParams);
    const totalOrders = parseInt(countResult.rows[0].total);

    // Get paginated orders
    const ordersQuery = `
      SELECT 
        o.id,
        o.user_id,
        o.paypal_order_id,
        o.paypal_subscription_id,
        o.status,
        o.amount,
        o.created_at,
        p.name as package_name,
        p.payment_type,
        p.price as package_price
      FROM orders o
      LEFT JOIN packages p ON o.package_id = p.id
      ${whereClause}
      ORDER BY o.${sortField} ${sortDirection}
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;

    queryParams.push(limit, offset);
    const ordersResult = await pool.query(ordersQuery, queryParams);

    const pagination = {
      current_page: page,
      per_page: limit,
      total_items: totalOrders,
      total_pages: Math.ceil(totalOrders / limit),
      has_next: page < Math.ceil(totalOrders / limit),
      has_prev: page > 1
    };

    res.json({
      orders: ordersResult.rows,
      pagination: pagination,
      filters_applied: { status, user_id, package_id },
      sort: { field: sortField, order: sortDirection }
    });

  } catch (err) {
    console.error('[ADMIN ORDERS] Error listing orders:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// GET /api/admin/orders/:id - Detailed view of specific order
app.get('/api/admin/orders/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;

  console.log(`[ADMIN ORDERS] Getting details for order: ${id}`);

  try {
    // Get order with package details
    const orderQuery = `
      SELECT 
        o.*,
        p.name as package_name,
        p.short_description,
        p.markdown_description,
        p.price as package_price,
        p.payment_type,
        p.subscription_interval,
        c.name as category_name
      FROM orders o
      LEFT JOIN packages p ON o.package_id = p.id
      LEFT JOIN categories c ON p.category_id = c.id
      WHERE o.id = $1
    `;

    const orderResult = await pool.query(orderQuery, [id]);

    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orderResult.rows[0];

    // Get associated package commands if package exists
    let commands = [];
    if (order.package_id) {
      const commandsQuery = `
        SELECT id, type, command, sort_order
        FROM package_commands
        WHERE package_id = $1
        ORDER BY type, sort_order ASC, created_at ASC
      `;
      
      const commandsResult = await pool.query(commandsQuery, [order.package_id]);
      commands = commandsResult.rows;
    }

    res.json({
      order: order,
      commands: commands
    });

  } catch (err) {
    console.error('[ADMIN ORDERS] Error getting order details:', err);
    res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// GET /api/admin/orders/stats - Dashboard statistics
app.get('/api/admin/orders/stats', cors(corsOptions), async (req, res) => {
  console.log('[ADMIN ORDERS] Getting dashboard statistics');

  try {
    // Status distribution
    const statusQuery = `
      SELECT 
        status,
        COUNT(*) as count,
        SUM(amount) as total_amount
      FROM orders
      GROUP BY status
      ORDER BY count DESC
    `;
    const statusResult = await pool.query(statusQuery);

    // Recent orders (last 10)
    const recentQuery = `
      SELECT 
        o.id,
        o.user_id,
        o.status,
        o.amount,
        o.created_at,
        p.name as package_name
      FROM orders o
      LEFT JOIN packages p ON o.package_id = p.id
      ORDER BY o.created_at DESC
      LIMIT 10
    `;
    const recentResult = await pool.query(recentQuery);

    // Top packages by order count
    const topPackagesQuery = `
      SELECT 
        p.name as package_name,
        p.id as package_id,
        COUNT(o.id) as order_count,
        SUM(o.amount) as total_revenue
      FROM packages p
      LEFT JOIN orders o ON p.id = o.package_id
      GROUP BY p.id, p.name
      HAVING COUNT(o.id) > 0
      ORDER BY order_count DESC
      LIMIT 5
    `;
    const topPackagesResult = await pool.query(topPackagesQuery);

    // Overall statistics - Fixed division by zero
    const overallQuery = `
      SELECT 
        COUNT(*) as total_orders,
        COUNT(DISTINCT user_id) as unique_customers,
        SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as total_revenue,
        CASE 
          WHEN COUNT(CASE WHEN status = 'completed' THEN 1 END) > 0 
          THEN AVG(CASE WHEN status = 'completed' THEN amount ELSE NULL END)
          ELSE 0 
        END as avg_order_value
      FROM orders
    `;
    const overallResult = await pool.query(overallQuery);

    res.json({
      status_distribution: statusResult.rows.map(row => ({
        status: row.status,
        count: parseInt(row.count),
        total_amount: parseFloat(row.total_amount || 0)
      })),
      recent_orders: recentResult.rows,
      top_packages: topPackagesResult.rows.map(row => ({
        package_name: row.package_name,
        package_id: row.package_id,
        order_count: parseInt(row.order_count),
        total_revenue: parseFloat(row.total_revenue || 0)
      })),
      overall_stats: {
        total_orders: parseInt(overallResult.rows[0].total_orders || 0),
        unique_customers: parseInt(overallResult.rows[0].unique_customers || 0),
        total_revenue: parseFloat(overallResult.rows[0].total_revenue || 0),
        avg_order_value: parseFloat(overallResult.rows[0].avg_order_value || 0)
      }
    });

  } catch (err) {
    console.error('[ADMIN ORDERS] Error getting statistics:', err);
    res.status(500).json({ error: 'Failed to fetch order statistics' });
  }
});

// PUT /api/admin/orders/:id/status - Manual status updates
app.put('/api/admin/orders/:id/status', cors(corsOptions), async (req, res) => {
  const { id } = req.params;
  const { status, reason } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status is required' });
  }

  const validStatuses = ['pending', 'completed', 'cancelled', 'failed', 'refunded'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  console.log(`[ADMIN ORDERS] Updating order ${id} status to: ${status}, reason: ${reason || 'N/A'}`);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get current order
    const currentOrderResult = await client.query('SELECT * FROM orders WHERE id = $1', [id]);
    
    if (currentOrderResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }

    const currentOrder = currentOrderResult.rows[0];
    const oldStatus = currentOrder.status;

    // Update status
    const updateResult = await client.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );

    const updatedOrder = updateResult.rows[0];

    await client.query('COMMIT');

    console.log(`[ADMIN ORDERS] Successfully updated order ${id} from ${oldStatus} to ${status}`);

    res.json({
      message: 'Order status updated successfully',
      order: updatedOrder,
      previous_status: oldStatus,
      new_status: status,
      reason: reason || null
    });

  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[ADMIN ORDERS] Error updating order status:', err);
    res.status(500).json({ error: 'Failed to update order status' });
  } finally {
    client.release();
  }
});

// DELETE /api/admin/orders/:id - Deletes a specific order by ID
app.delete('/api/admin/orders/:id', cors(corsOptions), async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};

  console.log(`[ADMIN ORDERS] Deleting order ${id}, reason: ${reason || 'N/A'}`);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get order details before deletion for logging
    const orderResult = await client.query(`
      SELECT 
        o.*,
        p.name as package_name
      FROM orders o
      LEFT JOIN packages p ON o.package_id = p.id
      WHERE o.id = $1
    `, [id]);

    if (orderResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }

    const orderToDelete = orderResult.rows[0];

    // Delete the order
    const deleteResult = await client.query('DELETE FROM orders WHERE id = $1 RETURNING id', [id]);

    if (deleteResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }

    await client.query('COMMIT');

    console.log(`[ADMIN ORDERS] Successfully deleted order ${id} - User: ${orderToDelete.user_id}, Package: ${orderToDelete.package_name}, Amount: ${orderToDelete.amount}`);

    res.json({
      message: 'Order deleted successfully',
      deleted_order: {
        id: orderToDelete.id,
        user_id: orderToDelete.user_id,
        package_name: orderToDelete.package_name,
        amount: orderToDelete.amount,
        status: orderToDelete.status,
        created_at: orderToDelete.created_at,
        paypal_order_id: orderToDelete.paypal_order_id,
        paypal_subscription_id: orderToDelete.paypal_subscription_id
      },
      deletion_reason: reason || null,
      deleted_at: new Date().toISOString()
    });

  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[ADMIN ORDERS] Error deleting order:', err);
    res.status(500).json({ error: 'Failed to delete order' });
  } finally {
    client.release();
  }
});

// PUT /api/news/update
// body JSON: { "id": 3, "text": "updated text" }
app.put('/api/news/update', cors(corsOptions), async (req, res) => {
  const { id, text } = req.body || {};
  
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Invalid body: id must be a positive integer' });
  }
  
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Invalid body: text is required' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(
      'UPDATE news SET text = $1 WHERE id = $2 RETURNING *',
      [text, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'News not found' });
    }
    
    res.json({ message: 'News updated successfully', news: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  } finally {
    client.release();
  }
});

// אתחול טבלה לפני שמתחילים להקשיב
ensureTable()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize DB:', err);
    process.exit(1);
  });
