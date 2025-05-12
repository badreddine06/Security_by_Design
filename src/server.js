const https = require("https");
const fs = require("fs");
const express = require("express");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fetch = require("node-fetch");
const winston = require("winston");
const morgan = require("morgan");
const bcrypt = require("bcrypt");
const session = require("express-session");
const fsPromises = require("fs/promises");
const bodyParser = require("body-parser");

const app = express();

// Clé SECRÈTE reCAPTCHA (test pour localhost)
const RECAPTCHA_SECRET = "6LcakjYrAAAAAPjA2DxiqwzNAT_Zr7mSseQFeaSP";

// Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/messages.log' }),
    new winston.transports.File({ filename: 'logs/access.log', level: 'http' }),
  ],
});

// Morgan: définir les tokens personnalisés AVANT l'utilisation
morgan.token('nom', (req) => req.body?.nom || '-');
morgan.token('email', (req) => req.body?.email || '-');

// Middleware de parsing JSON + URL-encoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logger HTTP avec les tokens personnalisés
app.use(morgan(':date[iso] - Nom: :nom, Email: :email', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Sécurisation des sessions
app.use(session({
  name: "connect.sid",
  secret: "une_phrase_secrete_complexe_et_unique",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Le flag Secure est activé en production
    sameSite: "strict",
    maxAge: 60 * 60 * 1000
  }
}));

// Sécurité avec Helmet
app.use(helmet({
  contentSecurityPolicy: false,
}));

// Limitation du nombre de requêtes
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// Middleware pour fichiers statiques
const publicDir = path.join(__dirname, "../public");
app.use(express.static(publicDir, {
  index: "index.html"
}));

// Authentification protégée
const requireAuth = (req, res, next) => {
  if (req.session.isAuthenticated) {
    return next();
  }
  res.redirect("/login");
};

// Routes publiques
app.get("/", (req, res) => {
  if (req.session.isAuthenticated) return res.redirect("/dashboard");
  res.sendFile(path.join(publicDir, "index.html"));
});

app.get("/login", (req, res) => {
  if (req.session.isAuthenticated) return res.redirect("/dashboard");
  res.sendFile(path.join(publicDir, "login.html"));
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const validUsername = "admin";
  const validPasswordHash = await bcrypt.hash("admin123", 10);

  const isUsernameValid = username === validUsername;
  const isPasswordValid = await bcrypt.compare(password, validPasswordHash);

  if (isUsernameValid && isPasswordValid) {
    req.session.isAuthenticated = true;
    req.session.username = username;
    logger.info(`Utilisateur ${username} connecté avec succès`);
    return res.json({ success: "Connexion réussie", redirect: "/dashboard" });
  } else {
    logger.warn(`Tentative de connexion échouée pour ${username}`);
    return res.status(401).json({ error: "Identifiants incorrects" });
  }
});

app.post("/logout", (req, res) => {

  req.session.destroy(err => {
    if (err) {
      logger.error("Erreur lors de la déconnexion:", err);
      return res.status(500).send("Erreur lors de la déconnexion");
    }
    res.redirect("/");

  });
});

// Routes protégées
app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(publicDir, "dashboard.html"));
});

app.get("/dashboard/username", requireAuth, (req, res) => {
  res.json({ username: req.session.username });
});

// Route de traitement du formulaire
app.post("/submit", requireAuth, async (req, res) => {
  const recaptchaToken = req.body["g-recaptcha-response"];
  const { nom, email, message } = req.body;

  if (!recaptchaToken) {
    logger.error('Erreur: Pas de token reCAPTCHA reçu');
    return res.status(400).json({ error: "Veuillez valider le reCAPTCHA." });
  }

  const isHuman = await verifyRecaptcha(recaptchaToken);
  if (!isHuman) {
    logger.error('Erreur: Échec de la vérification reCAPTCHA');
    return res.status(400).json({ error: "Échec de la vérification reCAPTCHA." });
  }

  const hashedMessage = await hashMessage(message);
  logger.info(`Nom: ${nom} | Email: ${email} | Message haché: ${hashedMessage}`);

  // ✅ Enregistrement dans message.json
  const newEntry = {
    timestamp: new Date().toISOString(),
    nom,
    email,
    message: hashedMessage
  };

  try {
    const filePath = path.join(__dirname, "../data/messages.json");

    let existingMessages = [];
    try {
      const fileData = await fsPromises.readFile(filePath, "utf-8");
      existingMessages = JSON.parse(fileData);
    } catch (readErr) {
      // Le fichier n'existe peut-être pas encore, on ignore l'erreur
    }

    existingMessages.push(newEntry);

    await fsPromises.writeFile(filePath, JSON.stringify(existingMessages, null, 2));
    res.json({ success: "Message envoyé avec succès !" });
  } catch (writeErr) {
    logger.error("Erreur lors de l'écriture dans messages.json:", writeErr);
    res.status(500).json({ error: "Erreur lors de l'enregistrement du message." });
  }
});

// Route pour l'inscription (info.json)
app.post("/register", async (req, res) => {
  const { username, password, "g-recaptcha-response": captcha } = req.body;

  if (!username || !password || !captcha) {
    return res.status(400).json({ error: "Champs manquants ou captcha manquant" });
  }

  // Vérifier le reCAPTCHA
  const captchaResult = await verifyRecaptcha(captcha);
  if (!captchaResult.success) {
    return res.status(401).json({ error: "Échec du reCAPTCHA" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hachage du mot de passe

    const userData = {
      username,
      password: hashedPassword,
      date: new Date().toISOString(),
    };

    const filePath = path.join(__dirname, "../data/info.json");

    // Lire les données existantes
    let existing = [];
    try {
      const raw = await fs.readFile(filePath, "utf8");
      existing = JSON.parse(raw);
    } catch (err) {
      // Le fichier n'existe pas encore ou est vide
      existing = [];
    }

    // Ajouter les nouvelles données
    existing.push(userData);

    // Réécrire le fichier
    await fs.writeFile(filePath, JSON.stringify(existing, null, 2));

    res.json({ success: "Utilisateur enregistré avec succès", redirect: "/login" });
  } catch (err) {
    logger.error("Erreur lors de l'enregistrement de l'utilisateur:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Fonction de vérification reCAPTCHA
async function verifyRecaptcha(token) {
  try {
    const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${RECAPTCHA_SECRET}&response=${token}`,
    });
    const data = await response.json();
    return data.success;
  } catch (error) {
    logger.error("Erreur reCAPTCHA:", error);
    return false;
  }
}

// Fonction de hachage du message
async function hashMessage(message) {
  const saltRounds = 10;
  return await bcrypt.hash(message, saltRounds);
}

// HTTPS
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, "../config/key_no_passphrase.pem")),
  cert: fs.readFileSync(path.join(__dirname, "../config/cert.pem")),
};

const PORT = process.env.PORT || 3000;
https.createServer(sslOptions, app).listen(PORT, () => {
  logger.info(`Serveur HTTPS démarré sur https://localhost:${PORT}`);
});
