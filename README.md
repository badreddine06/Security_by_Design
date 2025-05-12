# Security_by_Design


Vous trouverez ci-joint le rapport du projet au format PDF "Rapport_Securite_Formulaire.pdf"  ainsi qu’un fichier readme.txt contenant les informations essentielles sur l’installation, l’utilisation et les fonctionnalités du projet. Le rapport détaille les objectifs, la méthodologie, les résultats obtenus et les perspectives d’amélioration. Le fichier readme.txt sert de guide rapide pour comprendre et exploiter efficacement le projet.

# 📬 Formulaire de Contact Sécurisé

Projet local de formulaire de contact sécurisé, intégrant une authentification utilisateur, Google reCAPTCHA, sessions sécurisées et protection contre les vulnérabilités courantes (XSS, injections SQL, robots).

---

## 🔐 Fonctionnalités

- **Connexion sécurisée** : Authentification avec email et mot de passe haché (bcrypt)
- **Protection anti-robots** : Intégration de Google reCAPTCHA sur le formulaire et la page de login
- **Sécurité des sessions** : Cookies `HttpOnly`, `Secure`, `SameSite=Strict`
- **Protection des données** : Messages chiffrés avant stockage
- **HTTPS local** : Serveur en HTTPS avec certificat auto-signé
- **Logging** : Logs d’accès et de soumission dans `/logs/`

---

## 🚀 Installation rapide

```bash
git clone <repo>
cd formulaire_securise
npm install


🔏 Générer un certificat HTTPS local (si besoin)
bash

openssl req -nodes -new -x509 -keyout config/key.pem -out config/cert.pem -days 365


 Démarrage
En développement :

npm start

🌐 Accès
Naviguez vers :
https://localhost:3000


👤 Utilisateur de test
user : admin

Mot de passe : admin123
(Mot de passe haché stocké dans data/info.json)

✅ Tests recommandés
Vérifier Google reCAPTCHA (login + formulaire)


Contrôler les cookies dans les DevTools (HttpOnly, Secure)

Vérifier que les messages ne sont pas stockés en clair  il sont haché et stocké dans data/message.json)


👨‍💻 Auteur
Badreddine Khalil
EPSI Paris – Cours "Sécurité by Design"
2025


