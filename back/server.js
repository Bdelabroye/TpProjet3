// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

dotenv.config();

const JWT_SECRET = process.env.CODE;
const PORT = process.env.PORT;
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

// Exemple de route map (à compléter selon besoin)
app.get('/api/map', (req, res) => {
  // Récupérer les données GPS depuis la BDD et renvoyer en JSON
  res.json({ success: true, data: [] });
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

// Exemple de route protégée
app.get('/api/protected', authMiddleware, (req, res) => {
  res.json({ success: true, message: 'Accès autorisé', user: { id: req.user.sub, login: req.user.login } });
});

// Middleware global d'erreur
app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err);
  res.status(500).json({ success: false, message: 'Erreur serveur interne' });
});

// Route pour récupérer la dernière position de l'utilisateur connecté
app.get('/api/positions/last', authMiddleware, (req, res) => {
    const userId = req.user.sub; // récupéré depuis le token

    if (!userId) {
        return res.status(400).json({ success: false, message: "Utilisateur non identifié" });
    }

    const sql = `
        SELECT latitude AS lat, longitude AS lng, Date as created_at
        FROM GPS
        ORDER BY Date DESC
        LIMIT 1
    `;

    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error("Erreur MySQL :", err);
            return res.status(500).json({ success: false, message: "Erreur serveur" });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: "Aucune position trouvée" });
        }

        const pos = results[0];

        return res.json({
            success: true,
            lat: pos.lat,
            lng: pos.lng,
            timestamp: pos.created_at
        });
    });
});


// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});
