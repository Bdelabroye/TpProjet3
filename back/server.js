// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
var lat = 0.00;
var long = 0.00;

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

function xorDecrypt(data, key) { 
const output = Buffer.alloc(data.length);
for (let i = 0; i < data.length; i++) { 
output[i] = data[i] ^ key.charCodeAt(i % key.length);
} 
return output;
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

app.post('/api/gps/update', (req, res) => {
    const { auth_key, data } = req.body;

    // 1. Vérification de la clé d'authentification
    if (!auth_key || auth_key !== ARDUINO_TOKEN) {
        console.warn("Accès refusé : clé d'authentification invalide");
        return res.status(403).json({
            success: false,
            message: 'Accès refusé : clé invalide'
        });
    }

    // 2. Vérification du champ data
    if (!data) {
        return res.status(400).json({
            success: false,
            message: 'Champ data manquant'
        });
    }

    try {
        // 3. Décodage Base64
        const encryptedBuffer = Buffer.from(data, 'base64');

        // 4. Déchiffrement XOR
        const decryptedBuffer = xorDecrypt(encryptedBuffer, ENCRYPT_KEY);
        const decryptedText = decryptedBuffer.toString('utf8');

        // 5. Parsing du JSON
        const parsed = JSON.parse(decryptedText);
        const { latitude, longitude } = parsed;

        if (latitude === undefined || longitude === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Coordonnées GPS manquantes dans le message déchiffré'
            });
        }

        // 6. Mise à jour des variables globales
        lat = parseFloat(latitude);
        long = parseFloat(longitude);

        console.log(`GPS reçu : Lat=${lat}, Long=${long}`);

        return res.json({
            success: true,
            message: 'Coordonnées mises à jour avec succès'
        });

    } catch (err) {
        console.error("Erreur de déchiffrement ou parsing:", err.message);
        return res.status(500).json({
            success: false,
            message: 'Erreur de traitement des données'
        });
    }
});


// Route pour récupérer la dernière position de l'utilisateur connecté
app.get('/api/positions/last', authMiddleware, (req, res) => {
    const userId = req.user.sub; // récupéré depuis le token

    if (!userId) {
        return res.status(400).json({ success: false, message: "Utilisateur non identifié" });
    }

    return res.json({
            success: true,
            lat: lat,
            lng: long,
            });
          })
  
// Middleware global d'erreur
app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err);
  res.status(500).json({ success: false, message: 'Erreur serveur interne' });
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});