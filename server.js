require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', true); // Requerido para ver la IP real tras Coolify/Traefik
const PORT = process.env.PORT || 3001;
const API_KEY = process.env.API_KEY || '';
const NODE_ENV = process.env.NODE_ENV || 'development';

// ========================
// SECURITY MIDDLEWARE
// ========================

// Helmet - Security headers
app.use(helmet());

// CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : [];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, curl, etc.)
        if (!origin) return callback(null, true);
        if (allowedOrigins.length === 0) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('CORS no permitido'), false);
    },
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES) || 15) * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: { success: false, message: 'Demasiadas peticiones, intenta más tarde' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// JSON parser with size limit
app.use(express.json({ limit: '1mb' }));

// ========================
// API KEY AUTH MIDDLEWARE
// ========================
function requireApiKey(req, res, next) {
    if (NODE_ENV === 'development' && !API_KEY) {
        return next();
    }

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
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

// ========================
// INPUT SANITIZATION
// ========================
function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str.trim().replace(/[<>]/g, '').substring(0, 500);
}

function sanitizePersona(body) {
    return {
        nombre: sanitize(body.nombre),
        cedula: sanitize(body.cedula),
        edad: sanitize(body.edad || ''),
        telefono: sanitize(body.telefono),
        telefono_opcional: sanitize(body.telefono_opcional || ''),
        email: sanitize(body.email || ''),
        direccion: sanitize(body.direccion || ''),
        punto_referencia: sanitize(body.punto_referencia || ''),
        sector_barrio: sanitize(body.sector_barrio || ''),
        fecha_nacimiento: sanitize(body.fecha_nacimiento || ''),
        genero: ['M', 'F'].includes(body.genero) ? body.genero : 'M',
        registrant_id: sanitize(body.registrant_id || ''),
    };
}

function sanitizeRegistrant(body) {
    return {
        cedula: sanitize(body.cedula),
        nombres: sanitize(body.nombres),
        apellidos: sanitize(body.apellidos),
        telefono: sanitize(body.telefono),
        email: sanitize(body.email || ''),
        sexo: ['M', 'F'].includes(body.sexo) ? body.sexo : 'M',
        brand: sanitize(body.brand || ''),
        model: sanitize(body.model || ''),
        os_version: sanitize(body.os_version || ''),
        device_id: sanitize(body.device_id || ''),
    };
}

// ========================
// REQUEST LOGGING
// ========================
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const log = `[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`;
        if (res.statusCode >= 400) {
            console.error(`❌ ${log}`);
        } else {
            console.log(`✅ ${log}`);
        }
    });
    next();
});

// ========================
// SECURITY: IP BANNING & HONEYPOTS
// ========================
const bannedIPs = new Map(); // IP -> expiration context
const failedAttempts = new Map(); // IP -> count

const BAN_THRESHOLD = 5; // Bloquear tras 5 intentos fallidos
const BAN_DURATION = 24 * 60 * 60 * 1000; // 24 horas

function ipBanMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;

    if (bannedIPs.has(ip)) {
        const expiry = bannedIPs.get(ip);
        if (Date.now() < expiry) {
            console.log(`🚫 Bloqueado intento de IP baneada: ${ip}`);
            return res.status(403).json({ message: 'Acceso denegado permanentemente' });
        }
        bannedIPs.delete(ip);
    }
    next();
}

function recordFailedAttempt(req) {
    const ip = req.ip || req.connection.remoteAddress;
    const count = (failedAttempts.get(ip) || 0) + 1;
    failedAttempts.set(ip, count);

    if (count >= BAN_THRESHOLD) {
        console.error(`🚨 BANEANDO IP por múltiples fallos: ${ip}`);
        bannedIPs.set(ip, Date.now() + BAN_DURATION);
    }
}

app.use(ipBanMiddleware);

// Honeypots: Rutas atractivas para bots que causan ban inmediato
const honeypots = [
    '/.env', '/wp-admin', '/wp-login.php', '/config.php', '/index.php',
    '/.git', '/.vscode', '/graphql', '/api-docs', '/swagger'
];

honeypots.forEach(path => {
    app.all(path, (req, res) => {
        const ip = req.ip || req.connection.remoteAddress;
        console.error(`🪤 TRAMPA ACTIVADA: IP ${ip} intentó acceder a ${path}`);
        bannedIPs.set(ip, Date.now() + BAN_DURATION);
        res.status(403).json({ message: 'Trampa detectada' });
    });
});

// ========================
// DATABASE
// ========================
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'database.sqlite');
const dbDir = path.dirname(dbPath);
if (!require('fs').existsSync(dbDir)) {
    require('fs').mkdirSync(dbDir, { recursive: true });
}
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS personas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    cedula TEXT NOT NULL,
    edad TEXT DEFAULT '',
    telefono TEXT NOT NULL,
    telefono_opcional TEXT DEFAULT '',
    email TEXT DEFAULT '',
    direccion TEXT DEFAULT '',
    punto_referencia TEXT DEFAULT '',
    sector_barrio TEXT DEFAULT '',
    fecha_nacimiento TEXT DEFAULT '',
    genero TEXT DEFAULT 'M',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    received_at TEXT DEFAULT (datetime('now','localtime'))
  );
`);

// Auto-migrate new columns
const cols = db.prepare("PRAGMA table_info(personas)").all().map(c => c.name);
const newCols = [
    { name: 'edad', type: "TEXT DEFAULT ''" },
    { name: 'telefono_opcional', type: "TEXT DEFAULT ''" },
    { name: 'punto_referencia', type: "TEXT DEFAULT ''" },
    { name: 'sector_barrio', type: "TEXT DEFAULT ''" },
    { name: 'registrant_id', type: "TEXT DEFAULT ''" },
];
for (const col of newCols) {
    if (!cols.includes(col.name)) {
        db.exec(`ALTER TABLE personas ADD COLUMN ${col.name} ${col.type}`);
        console.log(`📦 Columna '${col.name}' agregada`);
    }
}

console.log('✅ Base de datos inicializada');

db.exec(`
  CREATE TABLE IF NOT EXISTS registrants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cedula TEXT NOT NULL UNIQUE,
    nombres TEXT NOT NULL,
    apellidos TEXT NOT NULL,
    telefono TEXT NOT NULL,
    email TEXT DEFAULT '',
    sexo TEXT DEFAULT 'M',
    brand TEXT DEFAULT '',
    model TEXT DEFAULT '',
    os_version TEXT DEFAULT '',
    device_id TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
`);

// ========================
// PUBLIC ROUTES (no auth needed)
// ========================
app.get('/api/health', (req, res) => {
    res.json({ success: true, status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0' });
});

// ========================
// API ROUTER V1
// ========================
const v1Router = express.Router();

// Public health check on v1 too
v1Router.get('/health', (req, res) => {
    res.json({ success: true, status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0', api: 'v1' });
});

// POST /registrants
v1Router.post('/registrants', requireApiKey, (req, res) => {
    try {
        const r = sanitizeRegistrant(req.body);

        if (!r.cedula || !r.nombres || !r.apellidos || !r.telefono) {
            return res.status(400).json({ success: false, message: 'Campos requeridos: cedula, nombres, apellidos, telefono' });
        }

        const stmt = db.prepare(`INSERT OR REPLACE INTO registrants (cedula, nombres, apellidos, telefono, email, sexo, brand, model, os_version, device_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        const result = stmt.run(r.cedula, r.nombres, r.apellidos, r.telefono, r.email, r.sexo, r.brand, r.model, r.os_version, r.device_id);

        console.log(`👤 Registrador registrado: ${r.nombres} ${r.apellidos} (Cédula: ${r.cedula}) [v1]`);
        res.status(201).json({ success: true, message: 'Usuario registrado exitosamente', data: { id: result.lastInsertRowid } });
    } catch (error) {
        console.error('❌ Error registrando usuario:', error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// POST /personas
v1Router.post('/personas', requireApiKey, (req, res) => {
    try {
        const p = sanitizePersona(req.body);

        if (!p.nombre || !p.cedula || !p.telefono) {
            return res.status(400).json({ success: false, message: 'Campos requeridos: nombre, cedula, telefono' });
        }

        const stmt = db.prepare(`INSERT INTO personas (nombre, cedula, edad, telefono, telefono_opcional, email, direccion, punto_referencia, sector_barrio, fecha_nacimiento, genero, registrant_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        const result = stmt.run(p.nombre, p.cedula, p.edad, p.telefono, p.telefono_opcional, p.email, p.direccion, p.punto_referencia, p.sector_barrio, p.fecha_nacimiento, p.genero, p.registrant_id);

        console.log(`📝 Persona registrada: ${p.nombre} (ID: ${result.lastInsertRowid}) [v1]`);
        res.status(201).json({ success: true, message: 'Persona registrada', data: { id: result.lastInsertRowid } });
    } catch (error) {
        console.error('❌ Error:', error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// POST /personas/batch
v1Router.post('/personas/batch', requireApiKey, (req, res) => {
    try {
        const { personas } = req.body;
        if (!Array.isArray(personas) || personas.length === 0) {
            return res.status(400).json({ success: false, message: 'Se requiere un array de personas' });
        }
        if (personas.length > 500) {
            return res.status(400).json({ success: false, message: 'Máximo 500 registros por batch' });
        }

        const stmt = db.prepare(`INSERT INTO personas (nombre, cedula, edad, telefono, telefono_opcional, email, direccion, punto_referencia, sector_barrio, fecha_nacimiento, genero, registrant_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

        const insertMany = db.transaction((items) => {
            const results = [];
            for (const item of items) {
                const p = sanitizePersona(item);
                if (!p.nombre || !p.cedula || !p.telefono) continue;
                const result = stmt.run(p.nombre, p.cedula, p.edad, p.telefono, p.telefono_opcional, p.email, p.direccion, p.punto_referencia, p.sector_barrio, p.fecha_nacimiento, p.genero, p.registrant_id);
                results.push(result.lastInsertRowid);
            }
            return results;
        });

        const ids = insertMany(personas);
        console.log(`📝 Batch: ${ids.length} personas registradas [v1]`);
        res.status(201).json({ success: true, message: `${ids.length} personas registradas`, data: { ids, count: ids.length } });
    } catch (error) {
        console.error('❌ Error en batch:', error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// GET /personas
v1Router.get('/personas', requireApiKey, (req, res) => {
    try {
        const { search, limit = 100, offset = 0 } = req.query;
        let personas;

        if (search) {
            const term = `%${sanitize(search)}%`;
            personas = db.prepare(`SELECT * FROM personas WHERE nombre LIKE ? OR cedula LIKE ? OR telefono LIKE ? OR email LIKE ? OR sector_barrio LIKE ?
        ORDER BY received_at DESC LIMIT ? OFFSET ?`).all(term, term, term, term, term, parseInt(limit), parseInt(offset));
        } else {
            personas = db.prepare('SELECT * FROM personas ORDER BY received_at DESC LIMIT ? OFFSET ?').all(parseInt(limit), parseInt(offset));
        }

        const total = db.prepare('SELECT COUNT(*) as count FROM personas').get();
        res.json({ success: true, data: personas, count: personas.length, total: total.count, api: 'v1' });
    } catch (error) {
        console.error('❌ Error:', error.message);
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// GET /personas/:id
v1Router.get('/personas/:id', requireApiKey, (req, res) => {
    try {
        const persona = db.prepare('SELECT * FROM personas WHERE id = ?').get(parseInt(req.params.id));
        if (!persona) return res.status(404).json({ success: false, message: 'Persona no encontrada' });
        res.json({ success: true, data: persona });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// DELETE /personas/:id
v1Router.delete('/personas/:id', requireApiKey, (req, res) => {
    try {
        const result = db.prepare('DELETE FROM personas WHERE id = ?').run(parseInt(req.params.id));
        if (result.changes === 0) return res.status(404).json({ success: false, message: 'Persona no encontrada' });
        console.log(`🗑️ Persona #${req.params.id} eliminada [v1]`);
        res.json({ success: true, message: 'Persona eliminada' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// GET /stats
v1Router.get('/stats', requireApiKey, (req, res) => {
    try {
        const total = db.prepare('SELECT COUNT(*) as count FROM personas').get();
        const today = db.prepare("SELECT COUNT(*) as count FROM personas WHERE date(received_at) = date('now','localtime')").get();
        res.json({ success: true, data: { total: total.count, today: today.count, banned: bannedIPs.size } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno' });
    }
});

// ASIGNAR EL ROUTER
app.use('/api/v1', v1Router);

// Compatibilidad temporal con /api (sin v1) para no romper versiones actuales
app.use('/api', v1Router);

// ========================
// 404 HANDLER
// ========================
app.use((req, res) => {
    recordFailedAttempt(req);
    res.status(404).json({ success: false, message: 'Ruta no permitida' });
});

// ========================
// ERROR HANDLER
// ========================
app.use((err, req, res, next) => {
    console.error('💥 Error no manejado:', err.message);
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
});

// ========================
// START
// ========================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 ElimAPP API v1.0.0`);
    console.log(`   Entorno:  ${NODE_ENV}`);
    console.log(`   Puerto:   ${PORT}`);
    console.log(`   Auth:     ${API_KEY ? '✅ API Key configurada' : '⚠️  Sin API Key (desarrollo)'}`);
    console.log(`   DB:       ${dbPath}\n`);
});

// ========================
// finished at 2026-03-24 (12:45)
// ========================
