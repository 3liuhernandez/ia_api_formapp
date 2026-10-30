require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');

const app = express();
// ========================
// HELPERS
// ========================
function isLoopback(ip) {
    if (!ip) return false;
    const cleanIp = ip.replace(/^::ffff:/, '');
    return cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost';
}

app.set('trust proxy', true);
const PORT = process.env.PORT || 3001;
const API_KEY = process.env.API_KEY || '';
const NODE_ENV = process.env.NODE_ENV || 'development';

// ========================
// SECURITY MIDDLEWARE
// ========================
app.use(helmet());

const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : [];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.length === 0) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('CORS no permitido'), false);
    },
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));


// ========================
// PUBLIC HEALTH & ROOT ROUTES (Exentos de rate limit y bans)
// ========================
app.get(['/', '/health', '/api/health'], (req, res) => {
    res.json({
        success: true,
        status: 'ok',
        service: 'ElimAPP API',
        version: '2.0.0',
        timestamp: new Date().toISOString()
    });
});

const limiter = rateLimit({
    windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES) || 15) * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: { success: false, message: 'Demasiadas peticiones, intenta más tarde' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false },
});
app.use('/api/', limiter);

app.use(express.json({ limit: '1mb' }));

// ========================
// API KEY AUTH
// ========================
function requireApiKey(req, res, next) {
    if (NODE_ENV === 'development' && !API_KEY) return next();
    const key = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
    if (!key) {
        recordFailedAttempt(req);
        return res.status(401).json({ success: false, message: 'API Key requerida' });
    }
    if (!API_KEY || !timingSafeEqual(key, API_KEY)) {
        recordFailedAttempt(req);
        return res.status(403).json({ success: false, message: 'API Key inválida' });
    }
    next();
}

function timingSafeEqual(a, b) {
    try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
    catch { return false; }
}

// ========================
// SANITIZATION
// ========================
function sanitize(str) {
    if (str === null || str === undefined) return '';
    if (typeof str === 'number') str = str.toString();
    if (typeof str !== 'string') return '';
    return str.trim().replace(/[<>]/g, '').substring(0, 500);
}

// Campos en inglés (igual que la app mobile)
function sanitizePerson(body) {
    return {
        dni: sanitize(body.dni),
        name: sanitize(body.name),
        last_name: sanitize(body.last_name || ''),
        phone: sanitize(body.phone),
        phone_optional: sanitize(body.phone_optional || ''),
        email: sanitize(body.email || ''),
        address: sanitize(body.address || ''),
        parish: sanitize(body.parish || ''),
        address_reference: sanitize(body.address_reference || ''),
        gender: ['M', 'F'].includes(body.gender) ? body.gender : 'M',
        birthday_date: sanitize(body.birthday_date || ''),
        comments: sanitize(body.comments || ''),
        visit_day: sanitize(body.visit_day || ''),
        visit_time: sanitize(body.visit_time || ''),
        registrant_dni: sanitize(body.registrant_dni || ''),
        // created_at opcional (timestamp del cliente, se preserva si viene)
        created_at: sanitize(body.created_at || ''),
    };
}

function sanitizeRegistrant(body) {
    return {
        dni: sanitize(body.dni),
        name: sanitize(body.name),
        last_name: sanitize(body.last_name || ''),
        phone: sanitize(body.phone),
        email: sanitize(body.email || ''),
        gender: ['M', 'F'].includes(body.gender) ? body.gender : 'M',
        brand: sanitize(body.brand || ''),
        model: sanitize(body.model || ''),
        os_version: sanitize(body.os_version || ''),
        device_id: sanitize(body.device_id || ''),
    };
}

// ========================
// LOGGING
// ========================
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const log = `[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`;
        if (res.statusCode >= 400) console.error(`❌ ${log}`);
        else console.log(`✅ ${log}`);
    });
    next();
});

// ========================
// IP BANNING & HONEYPOTS
// ========================
const failedAttempts = new Map();
const bannedIPs = new Map();
const BAN_THRESHOLD = 5;
const BAN_DURATION = 24 * 60 * 60 * 1000;

function ipBanMiddleware(req, res, next) {
    const ip = req.ip || req.socket?.remoteAddress;
    if (isLoopback(ip)) return next();
    try {
        const ban = db.prepare("SELECT expires_at FROM bans WHERE ip = ?").get(ip);
        if (ban) {
            const expiry = new Date(ban.expires_at).getTime();
            if (Date.now() < expiry) {
                console.log(`🚫 Intento bloqueado de IP baneada: ${ip}`);
                return res.status(403).json({ success: false, message: 'Acceso denegado. IP baneada temporalmente.' });
            } else {
                db.prepare("DELETE FROM bans WHERE ip = ?").run(ip);
            }
        }
    } catch (e) {
        console.error('Error checking bans:', e.message);
    }
    next();
}

function recordFailedAttempt(req) {
    const ip = req.ip || req.socket?.remoteAddress;
    if (isLoopback(ip)) return;
    const count = (failedAttempts.get(ip) || 0) + 1;
    failedAttempts.set(ip, count);
    if (count >= BAN_THRESHOLD) {
        const expiresAt = new Date(Date.now() + BAN_DURATION).toISOString();
        console.error(`🚨 BANEANDO IP: ${ip} hasta ${expiresAt}`);
        try {
            db.prepare("INSERT OR REPLACE INTO bans (ip, expires_at) VALUES (?, ?)").run(ip, expiresAt);
            failedAttempts.delete(ip);
        } catch (e) {
            console.error('Error recording ban:', e.message);
        }
    }
}

app.use(ipBanMiddleware);

const honeypots = [
    '/.env', '/wp-admin', '/wp-login.php', '/config.php', '/index.php',
    '/.git', '/.vscode', '/graphql', '/api-docs', '/swagger'
];

honeypots.forEach(hp => {
    app.all(hp, (req, res) => {
        const ip = req.ip || req.socket?.remoteAddress;
        if (isLoopback(ip)) return res.status(404).json({ message: 'Not found' });
        console.error(`🪤 TRAMPA: IP ${ip} intentó ${hp}`);
        const expiresAt = new Date(Date.now() + BAN_DURATION).toISOString();
        try {
            db.prepare("INSERT OR REPLACE INTO bans (ip, expires_at) VALUES (?, ?)").run(ip, expiresAt);
            bannedIPs.set(ip, Date.now() + BAN_DURATION);
        } catch (e) {
            console.error('Error al banear desde trampa:', e.message);
        }
        res.status(403).json({ message: 'Trampa detectada' });
    });
});

// ========================
// UPDATES CONFIG
// ========================
const publicDir = path.join(__dirname, 'public');
const updatesDir = path.join(publicDir, 'updates');
if (!fs.existsSync(updatesDir)) fs.mkdirSync(updatesDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, updatesDir),
    filename: (req, file, cb) => cb(null, file.originalname)
});

const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.originalname.endsWith('.apk')) cb(null, true);
        else cb(new Error('Solo se permiten archivos .apk'));
    }
});

app.use('/public', express.static(publicDir));

// ========================
// DATABASE + MIGRACIÓN
// ========================
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'database.sqlite');
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── Migración desde schema viejo (español) ──────────────────
function migrateOldSchema() {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name);

    // personas → people
    if (tables.includes('personas') && !tables.includes('people')) {
        console.log('🔄 Migrando personas → people...');
        db.exec(`
            CREATE TABLE people_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dni TEXT NOT NULL,
                name TEXT NOT NULL,
                last_name TEXT NOT NULL DEFAULT '',
                phone TEXT NOT NULL,
                phone_optional TEXT DEFAULT '',
                email TEXT DEFAULT '',
                address TEXT DEFAULT '',
                parish TEXT DEFAULT '',
                address_reference TEXT DEFAULT '',
                gender TEXT DEFAULT 'M',
                birthday_date TEXT DEFAULT '',
                comments TEXT DEFAULT '',
                visit_day TEXT DEFAULT '',
                visit_time TEXT DEFAULT '',
                registrant_dni TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now','localtime')),
                received_at TEXT DEFAULT (datetime('now','localtime'))
            );

            INSERT INTO people_new
                (id, dni, name, phone, phone_optional, email, address, parish,
                 address_reference, gender, birthday_date, comments, registrant_dni,
                 created_at, received_at)
            SELECT
                id, cedula, nombre, telefono, telefono_opcional, email, direccion, sector_barrio,
                punto_referencia, genero, fecha_nacimiento, observaciones, registrant_id,
                created_at, received_at
            FROM personas;

            DROP TABLE personas;
            ALTER TABLE people_new RENAME TO people;
        `);
        console.log('✅ Tabla people creada con datos migrados');
    }

    // registrants: renombrar columnas
    if (tables.includes('registrants')) {
        const cols = db.prepare("PRAGMA table_info(registrants)").all().map(c => c.name);
        if (cols.includes('cedula') && !cols.includes('dni')) {
            console.log('🔄 Migrando registrants a inglés...');
            db.exec(`
                CREATE TABLE registrants_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dni TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    last_name TEXT NOT NULL DEFAULT '',
                    phone TEXT NOT NULL,
                    email TEXT DEFAULT '',
                    gender TEXT DEFAULT 'M',
                    brand TEXT DEFAULT '',
                    model TEXT DEFAULT '',
                    os_version TEXT DEFAULT '',
                    device_id TEXT DEFAULT '',
                    created_at TEXT DEFAULT (datetime('now','localtime'))
                );

                INSERT INTO registrants_new
                    (id, dni, name, last_name, phone, email, gender, brand, model, os_version, device_id, created_at)
                SELECT
                    id, cedula, nombres, apellidos, telefono, email, sexo, brand, model, os_version, device_id, created_at
                FROM registrants;

                DROP TABLE registrants;
                ALTER TABLE registrants_new RENAME TO registrants;
            `);
            console.log('✅ Tabla registrants migrada');
        }
    }

    // users.role INTEGER → TEXT
    if (tables.includes('users')) {
        const sample = db.prepare("SELECT role FROM users LIMIT 1").get();
        if (sample && typeof sample.role === 'number') {
            console.log('🔄 Migrando users.role a string...');
            db.exec(`
                UPDATE users SET role = CASE
                    WHEN role >= 2 THEN 'admin'
                    ELSE 'register'
                END;
            `);
            console.log('✅ Roles migrados');
        }
    }
}

migrateOldSchema();

// ─── Crear tablas nuevas (si es fresh install) ───────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dni TEXT NOT NULL,
    name TEXT NOT NULL,
    last_name TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL,
    phone_optional TEXT DEFAULT '',
    email TEXT DEFAULT '',
    address TEXT DEFAULT '',
    parish TEXT DEFAULT '',
    address_reference TEXT DEFAULT '',
    gender TEXT DEFAULT 'M',
    birthday_date TEXT DEFAULT '',
    comments TEXT DEFAULT '',
    visit_day TEXT DEFAULT '',
    visit_time TEXT DEFAULT '',
    registrant_dni TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    received_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS registrants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dni TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    last_name TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL,
    email TEXT DEFAULT '',
    gender TEXT DEFAULT 'M',
    brand TEXT DEFAULT '',
    model TEXT DEFAULT '',
    os_version TEXT DEFAULT '',
    device_id TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'register' CHECK (role IN ('register','admin')),
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS app_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    filename TEXT NOT NULL,
    release_notes TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE INDEX IF NOT EXISTS idx_people_dni            ON people(dni);
  CREATE INDEX IF NOT EXISTS idx_people_registrant_dni ON people(registrant_dni);
  CREATE INDEX IF NOT EXISTS idx_people_received_at    ON people(received_at);
`);

console.log('✅ Base de datos inicializada');

// Limpiar bans accidentales de localhost/loopback
try {
    const unbanned = db.prepare("DELETE FROM bans WHERE ip IN ('127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost')").run();
    if (unbanned.changes > 0) {
        console.log(`🧹 Bans de localhost eliminados automáticamente (${unbanned.changes})`);
    }
} catch (e) {
    console.error('Error limpiando bans de localhost:', e.message);
}

// Admin default (si no existe ningún user)
try {
    const count = db.prepare('SELECT COUNT(*) as n FROM users').get();
    if (count && count.n === 0) {
        db.prepare('INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)').run(
            'iuser', 'Iuser3548**', 'Admin iUser', 'admin'
        );
        console.log('👤 Usuario admin creado en la API');
    }
} catch (e) {
    console.error('Error initializing admin user:', e.message);
}

// ========================
// PUBLIC ROUTES
// ========================
app.get('/api/health', (req, res) => {
    res.json({ success: true, status: 'ok', timestamp: new Date().toISOString(), version: '2.0.0' });
});

// ========================
// API V1
// ========================
const v1Router = express.Router();

v1Router.get('/health', (req, res) => {
    res.json({ success: true, status: 'ok', timestamp: new Date().toISOString(), version: '2.0.0', api: 'v1' });
});

// POST /auth/login
v1Router.post('/auth/login', requireApiKey, (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Usuario y contraseña requeridos' });
        }
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user || user.password !== password) {
            recordFailedAttempt(req);
            return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
        }

        const mockToken = Buffer.from(`${user.id}:${user.username}:${Date.now()}`).toString('base64');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        console.log(`🔐 Login: ${user.username} (role: ${user.role})`);

        res.json({
            success: true,
            message: 'Login exitoso',
            data: {
                id: user.id,
                username: user.username,
                name: user.name,
                role: user.role,           // ← ahora 'register' | 'admin'
                token: mockToken,
                expires_at: expiresAt
            }
        });
    } catch (error) {
        console.error('❌ Error en login:', error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// POST /auth/unban
v1Router.post('/auth/unban', requireApiKey, (req, res) => {
    try {
        const { ip } = req.body;
        if (!ip) return res.status(400).json({ success: false, message: 'IP requerida' });
        const result = db.prepare('DELETE FROM bans WHERE ip = ?').run(ip);
        failedAttempts.delete(ip);
        if (result.changes > 0) {
            res.json({ success: true, message: `IP ${ip} desbaneada exitosamente` });
        } else {
            res.status(404).json({ success: false, message: 'La IP no estaba baneada' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// POST /registrants
v1Router.post('/registrants', requireApiKey, (req, res) => {
    try {
        const r = sanitizeRegistrant(req.body);
        if (!r.dni || !r.name || !r.last_name || !r.phone) {
            return res.status(400).json({
                success: false,
                message: 'Campos requeridos: dni, name, last_name, phone'
            });
        }

        const stmt = db.prepare(`
            INSERT INTO registrants (dni, name, last_name, phone, email, gender, brand, model, os_version, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dni) DO UPDATE SET
                name = excluded.name,
                last_name = excluded.last_name,
                phone = excluded.phone,
                email = excluded.email,
                gender = excluded.gender,
                brand = excluded.brand,
                model = excluded.model,
                os_version = excluded.os_version,
                device_id = excluded.device_id
        `);
        stmt.run(r.dni, r.name, r.last_name, r.phone, r.email, r.gender, r.brand, r.model, r.os_version, r.device_id);

        const row = db.prepare('SELECT id FROM registrants WHERE dni = ?').get(r.dni);

        console.log(`👤 Registrador: ${r.name} ${r.last_name} (DNI: ${r.dni})`);
        res.status(201).json({
            success: true,
            message: 'Registrador guardado',
            data: { id: row.id }
        });
    } catch (error) {
        console.error('❌ Error registrando:', error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// GET /registrants
v1Router.get('/registrants', requireApiKey, (req, res) => {
    try {
        const { search, limit = 100, offset = 0 } = req.query;
        let registrants;
        if (search === 'today') {
            registrants = db.prepare(`
                SELECT * FROM registrants
                WHERE created_at >= date('now','localtime')
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            `).all(parseInt(limit), parseInt(offset));
        } else if (search) {
            const term = `%${sanitize(search)}%`;
            registrants = db.prepare(`
                SELECT * FROM registrants
                WHERE name LIKE ? OR last_name LIKE ? OR dni LIKE ? OR email LIKE ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            `).all(term, term, term, term, parseInt(limit), parseInt(offset));
        } else {
            registrants = db.prepare(`
                SELECT * FROM registrants ORDER BY created_at DESC LIMIT ? OFFSET ?
            `).all(parseInt(limit), parseInt(offset));
        }

        const total = db.prepare('SELECT COUNT(*) as count FROM registrants').get();
        res.json({ success: true, data: registrants, count: registrants.length, total: total.count, api: 'v1' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// POST /people  (antes /personas)
v1Router.post('/people', requireApiKey, (req, res) => {
    try {
        const p = sanitizePerson(req.body);
        if (!p.name || !p.dni || !p.phone) {
            return res.status(400).json({ success: false, message: 'Campos requeridos: name, dni, phone' });
        }

        const stmt = db.prepare(`
            INSERT INTO people
                (dni, name, last_name, phone, phone_optional, email, address, parish,
                 address_reference, gender, birthday_date, comments, visit_day, visit_time,
                 registrant_dni, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), datetime('now','localtime')))
        `);
        const result = stmt.run(
            p.dni, p.name, p.last_name, p.phone, p.phone_optional, p.email, p.address, p.parish,
            p.address_reference, p.gender, p.birthday_date, p.comments, p.visit_day, p.visit_time,
            p.registrant_dni, p.created_at
        );

        console.log(`📝 Persona: ${p.name} ${p.last_name} (ID: ${result.lastInsertRowid})`);
        res.status(201).json({
            success: true,
            message: 'Persona registrada',
            data: { id: result.lastInsertRowid }
        });
    } catch (error) {
        console.error('❌ Error:', error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// POST /people/batch
v1Router.post('/people/batch', requireApiKey, (req, res) => {
    try {
        const { people } = req.body;
        if (!Array.isArray(people) || people.length === 0) {
            return res.status(400).json({ success: false, message: 'Se requiere un array de people' });
        }
        if (people.length > 500) {
            return res.status(400).json({ success: false, message: 'Máximo 500 registros por batch' });
        }

        const stmt = db.prepare(`
            INSERT INTO people
                (dni, name, last_name, phone, phone_optional, email, address, parish,
                 address_reference, gender, birthday_date, comments, visit_day, visit_time,
                 registrant_dni, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), datetime('now','localtime')))
        `);

        const insertMany = db.transaction((items) => {
            const ids = [];
            for (const item of items) {
                const p = sanitizePerson(item);
                if (!p.name || !p.dni || !p.phone) continue;
                const r = stmt.run(
                    p.dni, p.name, p.last_name, p.phone, p.phone_optional, p.email, p.address, p.parish,
                    p.address_reference, p.gender, p.birthday_date, p.comments, p.visit_day, p.visit_time,
                    p.registrant_dni, p.created_at
                );
                ids.push(r.lastInsertRowid);
            }
            return ids;
        });

        const ids = insertMany(people);
        console.log(`📝 Batch: ${ids.length} personas registradas`);
        res.status(201).json({
            success: true,
            message: `${ids.length} personas registradas`,
            data: { ids, count: ids.length }
        });
    } catch (error) {
        console.error('❌ Error en batch:', error.message);
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// GET /people
v1Router.get('/people', requireApiKey, (req, res) => {
    try {
        const { search, limit = 100, offset = 0, start_date, end_date } = req.query;
        let queryParams = [];
        let conditions = [];

        if (search) {
            const term = `%${sanitize(search)}%`;
            conditions.push('(name LIKE ? OR last_name LIKE ? OR dni LIKE ? OR phone LIKE ? OR email LIKE ? OR parish LIKE ?)');
            queryParams.push(term, term, term, term, term, term);
        }

        if (start_date && end_date) {
            conditions.push('date(received_at) >= date(?) AND date(received_at) <= date(?)');
            queryParams.push(sanitize(start_date), sanitize(end_date));
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

        const people = db.prepare(`
            SELECT * FROM people
            ${whereClause}
            ORDER BY received_at DESC
            LIMIT ? OFFSET ?
        `).all(...queryParams, parseInt(limit), parseInt(offset));

        const total = db.prepare(`SELECT COUNT(*) as count FROM people ${whereClause}`).get(...queryParams);

        res.json({ success: true, data: people, count: people.length, total: total.count, api: 'v1' });
    } catch (error) {
        console.error('❌ Error:', error.message);
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// GET /people/:id
v1Router.get('/people/:id', requireApiKey, (req, res) => {
    try {
        const person = db.prepare('SELECT * FROM people WHERE id = ?').get(parseInt(req.params.id));
        if (!person) return res.status(404).json({ success: false, message: 'No encontrada' });
        res.json({ success: true, data: person });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// DELETE /people/:id
v1Router.delete('/people/:id', requireApiKey, (req, res) => {
    try {
        const result = db.prepare('DELETE FROM people WHERE id = ?').run(parseInt(req.params.id));
        if (result.changes === 0) return res.status(404).json({ success: false, message: 'No encontrada' });
        console.log(`🗑️ Persona #${req.params.id} eliminada`);
        res.json({ success: true, message: 'Persona eliminada' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// GET /stats
v1Router.get('/stats', requireApiKey, (req, res) => {
    try {
        const total = db.prepare('SELECT COUNT(*) as count FROM people').get();
        const today = db.prepare("SELECT COUNT(*) as count FROM people WHERE date(received_at) = date('now','localtime')").get();
        const banned = db.prepare('SELECT COUNT(*) as count FROM bans').get();
        res.json({ success: true, data: { total: total.count, today: today.count, banned: banned.count } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// ========================
// APP UPDATES
// ========================
v1Router.get('/updates/latest', (req, res) => {
    try {
        const latest = db.prepare('SELECT * FROM app_updates ORDER BY id DESC LIMIT 1').get();
        if (!latest) {
            return res.json({
                success: true,
                data: { version: '1.0.0', downloadUrl: null, releaseNotes: 'Sin actualizaciones' }
            });
        }
        const protocol = req.headers['x-forwarded-proto'] || req.protocol;
        const host = req.get('host');
        const downloadUrl = `${protocol}://${host}/public/updates/${latest.filename}`;
        res.json({
            success: true,
            data: {
                version: latest.version,
                downloadUrl,
                releaseNotes: latest.release_notes,
                date: latest.created_at
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error al consultar actualizaciones' });
    }
});

v1Router.post('/updates/upload', requireApiKey, (req, res) => {
    upload.single('apk')(req, res, (err) => {
        if (err) return res.status(400).json({ success: false, message: err.message });
        if (!req.file) return res.status(400).json({ success: false, message: 'Archivo APK requerido' });

        const { version, releaseNotes } = req.body;
        if (!version) return res.status(400).json({ success: false, message: 'Versión requerida' });

        try {
            db.prepare('INSERT INTO app_updates (version, filename, release_notes) VALUES (?, ?, ?)')
                .run(version, req.file.filename, releaseNotes || '');
            console.log(`🚀 Nuevo APK: Versión ${version}`);
            res.json({
                success: true,
                message: 'Update publicado con éxito',
                data: { version, filename: req.file.filename }
            });
        } catch (error) {
            res.status(500).json({ success: false, message: 'Error en base de datos' });
        }
    });
});

// ========================
// COMPAT: rutas /personas → /people (temporal)
// Para clientes viejos que aún no migraron
// ========================
v1Router.post('/personas', requireApiKey, (req, res, next) => {
    req.url = '/people';
    v1Router.handle(req, res, next);
});
v1Router.get('/personas', requireApiKey, (req, res, next) => {
    req.url = '/people';
    v1Router.handle(req, res, next);
});

app.use('/api/v1', v1Router);
app.use('/api', v1Router);

// ========================
// 404 & ERROR
// ========================
app.use((req, res) => {
    const ip = req.ip || req.socket?.remoteAddress;
    if (!['/favicon.ico', '/robots.txt'].includes(req.path) && !isLoopback(ip)) {
        recordFailedAttempt(req);
    }
    res.status(404).json({ success: false, message: 'Ruta no permitida' });
});

app.use((err, req, res, next) => {
    console.error('💥 Error no manejado:', err.message);
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
});

// ========================
// START
// ========================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 ElimAPP API v2.0.0 (English schema)`);
    console.log(`   Entorno: ${NODE_ENV}`);
    console.log(`   Puerto:  ${PORT}`);
    console.log(`   Auth:    ${API_KEY ? '✅ API Key configurada' : '⚠️  Sin API Key (dev)'}`);
    console.log(`   DB:      ${dbPath}\n`);
});