// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const net = require('net');

dotenv.config();

const JWT_SECRET = process.env.CODE;
const PORT = process.env.PORT;
const AUTH_KEY = process.env.ARDUINO_TOKEN
// --- Utilitaires pour les tokens ---
function extractToken(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  return authHeader.slice(7);
}

// Simple blacklist en mémoire (pour tests). En production, utiliser Redis/DB avec TTL.
const revokedTokens = new Set();
function revokeToken(jti) { if (jti) revokedTokens.add(jti); }
function isRevoked(jti) { return jti && revokedTokens.has(jti); }

// Middleware pour vérifier le token JWT
function authMiddleware(req, res, next) {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ success: false, message: 'Token manquant' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (isRevoked(payload.jti)) return res.status(401).json({ success: false, message: 'Token révoqué' });
    req.user = payload;
    next(); 
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Token invalide ou expiré' });
  }
}

// --- App et middlewares ---
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir les fichiers statiques (front)
app.use(express.static('/var/www/html/TpProjet3/'));

// --- Connexion MySQL ---
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect(err => {
  if (err) {
    console.error('Erreur de connexion MySQL :', err.message);
  } else {
    console.log('Connecté à la base de données MySQL');
  }
});

// --- Routes publiques ---
app.get('/', (req, res) => {
    res.sendFile(path.join('/var/www/html/TpProjet3/front', 'index.html'));
});

// Route de connexion
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) {
    return res.status(400).json({ success: false, message: 'Login et mot de passe requis' });
  }

  const query = 'SELECT * FROM User WHERE Login = ?';
  db.query(query, [login], (err, results) => {
    if (err) {
      console.error('Erreur lors de la requête MySQL :', err.message);
      return res.status(500).json({ success: false, message: 'Erreur serveur' });
    }

    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Nom d\'utilisateur inexistant' });
    }

    const user = results[0];
    bcrypt.compare(password, user.Password, (err, isMatch) => {
      if (err) {
        console.error('Erreur lors de la comparaison des mots de passe :', err.message);
        return res.status(500).json({ success: false, message: 'Erreur serveur' });
      }

      if (!isMatch) {
        return res.status(401).json({ success: false, message: 'Nom d\'utilisateur ou mot de passe incorrect' });
      }

      const jti = uuidv4();
      const payload = { sub: user.Id || user.id || user.ID, login: user.Login, jti };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '4h' });

      return res.json({ success: true, message: 'Connexion réussie', token });
    });
  });
});

// Route d'inscription
app.post('/api/inscription', (req, res) => {
  const { prenom, nom, email, username, password } = req.body;
  if (!prenom || !nom || !email || !username || !password) {
    return res.status(400).json({ success: false, message: 'Tous les champs sont requis' });
  }

  const checkQuery = 'SELECT * FROM User WHERE Login = ? OR Mail = ?';
  db.query(checkQuery, [username, email], (err, results) => {
    if (err) {
      console.error('Erreur lors de la requête MySQL :', err.message);
      return res.status(500).json({ success: false, message: 'Erreur serveur' });
    }

    if (results.length > 0) {
      return res.status(409).json({ success: false, message: 'Nom d\'utilisateur ou email déjà utilisé' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Erreur lors du hachage du mot de passe :', err.message);
        return res.status(500).json({ success: false, message: 'Erreur serveur' });
      }

      const insertQuery = 'INSERT INTO User (Nom, Prénom, Mail, Login, Password) VALUES (?, ?, ?, ?, ?)';
      db.query(insertQuery, [nom, prenom, email, username, hashedPassword], (err, results) => {
        if (err) {
          console.error('Erreur lors de l\'insertion dans la base de données :', err.message);
          return res.status(500).json({ success: false, message: 'Erreur serveur' });
        }

        // Récupérer l'ID inséré si besoin
        const userId = results.insertId;
        const jti = uuidv4();
        const payload = { sub: userId, login: username, jti };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '4h' });

        return res.json({ success: true, message: 'Inscription réussie', token });
      });
    });
  });
});

// Route pour valider le token (utilise authMiddleware si on veut)
app.get('/api/auth/validate', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ ok: false, message: 'Token manquant' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (isRevoked(payload.jti)) return res.status(401).json({ ok: false, message: 'Token révoqué' });

    return res.status(200).json({
      ok: true,
      userId: payload.sub,
      login: payload.login,
      exp: payload.exp
    });
  } catch (err) {
    return res.status(401).json({ ok: false, message: 'Token invalide ou expiré' });
  }
});

// Route de logout (révocation du jti)
app.post('/api/auth/logout', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(200).json({ success: true, message: 'Déconnecté' }); // idempotent

  try {
    const payload = jwt.decode(token);
    if (payload && payload.jti) {
      revokeToken(payload.jti);
    }
  } catch (e) {
    // ignore decode errors
  }

  return res.status(200).json({ success: true, message: 'Déconnecté' });
});

// Route Arduino : Réception des trames GPS
const ARDUINO_TOKEN = process.env.ARDUINO_TOKEN;
const ENCRYPT_KEY = process.env.ENCRYPT;

function isAdmin(userId, cb) {
  db.query(
    'SELECT Admin FROM User WHERE id = ? OR Id = ? OR ID = ? LIMIT 1',
    [userId, userId, userId],
    (err, rows) => {
      if (err) return cb(err, false);
      if (!rows || rows.length === 0) return cb(null, false);
      return cb(null, !!rows[0].Admin);
    }
  );
}

app.get('/api/rfid/logs', authMiddleware, (req, res) => {
  const limitRaw = parseInt(req.query.limit || '30', 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 30;

  db.query(
    'SELECT id, uid, person_name, door, allowed, created_at FROM rfid_logs ORDER BY id DESC LIMIT ?',
    [limit],
    (err, rows) => {
      if (err) {
        console.error('RFID logs error:', err);
        return res.status(500).json({ success: false, message: 'Erreur DB logs' });
      }
      return res.json({ success: true, rows: rows || [] });
    }
  );
});

app.post('/api/rfid/enroll', authMiddleware, (req, res) => {
  const userId = req.user?.sub;

  const full_name = String(req.body?.full_name || '').trim();
  const uid = String(req.body?.uid || '').trim();
  const enabled = req.body?.enabled ? 1 : 0;

  if (!full_name || !uid) {
    return res.status(400).json({ success: false, message: 'full_name et uid requis' });
  }

  isAdmin(userId, (err, ok) => {
    if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
    if (!ok) return res.status(403).json({ success: false, message: 'Admin requis' });

    db.query(
      'INSERT INTO rfid_people (full_name, uid, enabled) VALUES (?, ?, ?)',
      [full_name, uid, enabled],
      (err2) => {
        if (err2) {
          const msg = String(err2.message || '');
          if (msg.includes('Duplicate') || msg.includes('duplicate') || msg.includes('UNIQUE')) {
            return res.status(409).json({ success: false, message: 'UID déjà enregistré' });
          }
          console.error('RFID enroll error:', err2);
          return res.status(500).json({ success: false, message: 'Erreur DB enroll' });
        }
        return res.json({ success: true, message: 'Carte enregistrée' });
      }
    );
  });
});

app.get('/api/rfid/users', authMiddleware, (req, res) => {
  const userId = req.user?.sub;

  isAdmin(userId, (err, ok) => {
    if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
    if (!ok) return res.status(403).json({ success: false, message: 'Admin requis' });

    db.query(
      'SELECT id, full_name, uid, enabled, created_at FROM rfid_people ORDER BY id DESC',
      (err2, rows) => {
        if (err2) {
          console.error('RFID users error:', err2);
          return res.status(500).json({ success: false, message: 'Erreur DB users' });
        }
        return res.json({ success: true, rows: rows || [] });
      }
    );
  });
});

app.delete('/api/rfid/users/:id', authMiddleware, (req, res) => {
  const userId = req.user?.sub;
  const id = parseInt(req.params.id, 10);

  if (!Number.isFinite(id)) {
    return res.status(400).json({ success: false, message: 'ID invalide' });
  }

  isAdmin(userId, (err, ok) => {
    if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
    if (!ok) return res.status(403).json({ success: false, message: 'Admin requis' });

    db.query('DELETE FROM rfid_people WHERE id = ?', [id], (err2, result) => {
      if (err2) {
        console.error('RFID delete error:', err2);
        return res.status(500).json({ success: false, message: 'Erreur DB delete' });
      }
      if (!result || result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'Carte introuvable' });
      }

      return res.json({ success: true, message: 'Supprimé' });
    });
  });
});

const TCP_BIND = process.env.TCP_BIND || '0.0.0.0';
const TCP_PORT = parseInt(process.env.TCP_PORT || '56180', 10);
const RFID_SHARED_KEY = process.env.RFID_SHARED_KEY || null;

function parseBadgeLine(line) {
  // Ex: BADGE;UID=04A1B2C3D4;DOOR=MAIN;KEY=MONSECRET
  const parts = line.trim().split(';');
  const msg = {};
  if (parts[0] && !parts[0].includes('=')) msg.TYPE = parts[0].trim().toUpperCase();

  for (const p of parts) {
    const i = p.indexOf('=');
    if (i === -1) continue;
    const k = p.slice(0, i).trim().toUpperCase();
    const v = p.slice(i + 1).trim();
    msg[k] = v;
  }
  return msg;
}

const tcpServer = net.createServer((socket) => {
  socket.setEncoding('utf8');
  let buffer = '';

  socket.on('data', (chunk) => {
    buffer += chunk;

    let idx;
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);

      if (!line) continue;

      const msg = parseBadgeLine(line);
      if (msg.TYPE && msg.TYPE !== 'BADGE') continue;

      const uid = msg.UID;
      const door = msg.DOOR || 'MAIN';
      const key = msg.KEY || null;

      if (!uid) continue;

      // Sécurité minimale
      if (RFID_SHARED_KEY && key !== RFID_SHARED_KEY) {
        db.query(
          'INSERT INTO rfid_logs (uid, person_name, door, allowed, raw_msg) VALUES (?, NULL, ?, 0, ?)',
          [uid, door, line],
          () => {}
        );
        try { socket.write(`RESULT;UID=${uid};ALLOWED=0;REASON=BAD_KEY\n`); } catch {}
        continue;
      }

      // Cherche la personne
      db.query('SELECT full_name, enabled FROM rfid_people WHERE uid = ? LIMIT 1', [uid], (err, rows) => {
        const found = !err && rows && rows.length > 0;
        const enabled = found ? !!rows[0].enabled : false;
        const name = found ? rows[0].full_name : null;
        const allowed = found && enabled;

        db.query(
          'INSERT INTO rfid_logs (uid, person_name, door, allowed, raw_msg) VALUES (?, ?, ?, ?, ?)',
          [uid, name, door, allowed ? 1 : 0, line],
          () => {}
        );

        try { socket.write(`RESULT;UID=${uid};ALLOWED=${allowed ? 1 : 0}\n`); } catch {}
      });
    }
  });

  socket.on('error', () => {});
});

tcpServer.listen(TCP_PORT, TCP_BIND, () => {
  console.log(`[RFID] TCP listening on ${TCP_BIND}:${TCP_PORT}`);
});

// -----------------------------------------------------------
// Route HTTP pour recevoir les UID envoyés par le programme C++
// -----------------------------------------------------------
app.post('/api/rfid/update', (req, res) => {
  try {
    const authKey = req.body?.auth_key;
    const encryptedBase64 = req.body?.data;

    if (!authKey || !encryptedBase64) {
      return res.status(400).json({ success: false, message: "auth_key et data requis" });
    }

    // Vérification clé d'authentification
    if (authKey !== AUTH_KEY) {
      return res.status(403).json({ success: false, message: "Clé d'authentification invalide" });
    }

    // Décodage Base64
    const encrypted = Buffer.from(encryptedBase64, "base64");

    // Déchiffrement XOR
    const key = Buffer.from(ENCRYPT_KEY);
    const decrypted = Buffer.alloc(encrypted.length);

    for (let i = 0; i < encrypted.length; i++) {
      decrypted[i] = encrypted[i] ^ key[i % key.length];
    }

    const jsonStr = decrypted.toString("utf8");
    console.log("[RFID] JSON déchiffré :", jsonStr);

    let payload;
    try {
      payload = JSON.parse(jsonStr);
    } catch (e) {
      return res.status(400).json({ success: false, message: "JSON déchiffré invalide" });
    }

    const uid = String(payload.uid || "").trim();
    if (!uid) {
      return res.status(400).json({ success: false, message: "UID manquant" });
    }

    // Recherche dans la base
    db.query(
      "SELECT full_name, enabled FROM rfid_people WHERE uid = ? LIMIT 1",
      [uid],
      (err, rows) => {
        if (err) {
          console.error("Erreur DB RFID:", err);
          return res.status(500).json({ success: false, message: "Erreur DB" });
        }

        const found = rows.length > 0;
        const enabled = found ? !!rows[0].enabled : false;
        const name = found ? rows[0].full_name : null;
        const allowed = found && enabled;

        // Log
        db.query(
          "INSERT INTO rfid_logs (uid, person_name, door, allowed, raw_msg) VALUES (?, ?, ?, ?, ?)",
          [uid, name, "HTTP", allowed ? 1 : 0, jsonStr]
        );

        return res.json({
          success: true,
          uid,
          allowed,
          person: name || null
        });
      }
    );
  } catch (err) {
    console.error("Erreur /api/rfid/update:", err);
    return res.status(500).json({ success: false, message: "Erreur serveur interne" });
  }
});


// Middleware global d'erreur
app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err);
  res.status(500).json({ success: false, message: 'Erreur serveur interne' });
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});