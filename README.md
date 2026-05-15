#  Password Security Checker

**Projet Sécurité Informatique — 2025/2026**

---

## Description

Application web permettant d'analyser la robustesse d'un mot de passe en temps réel, sans envoi de données sur un serveur. Tout le traitement se fait côté client (navigateur).

## Fonctionnalités

- Vérification de 6 critères de sécurité (longueur, majuscules, chiffres, caractères spéciaux...)
- Barre de force visuelle mise à jour en temps réel
- Estimation du temps de crackage par brute-force
- Tableau comparatif de mots de passe types
- Conseils de bonnes pratiques

## Technologies utilisées

- HTML5
- CSS3
- JavaScript (Vanilla, sans framework)

## Structure du projet

```
password-checker/
├── index.html        ← Page principale
├── css/
│   └── style.css     ← Styles de l'interface
├── js/
│   └── checker.js    ← Logique d'analyse
├── rapport/
│   └── rapport.docx  ← Rapport explicatif
└── README.md         ← Ce fichier
security/
└── phishing-detector/
    ├── train_model.py   ← entraîne Random Forest
    ├── app.py           ← analyse et retourne la prédiction en JSON
    └── templates/
        └── index.html   ← page commun
```

## Lancement

Bonjour,

Voici mon projet de sécurité informatique :

1. **Démonstration en ligne (Password Checker)** :  
   https://elghazouaninoura9-png.github.io/projet-securite/

2. **Code source complet (dépôt GitHub)** :  
   https://github.com/elghazouaninoura9-png/projet-securite

   → Le code du Phishing URL Detector (Flask + Random Forest) est dans les fichiers `app.py` et `templates/`

3. **Pour exécuter le détecteur de phishing localement** :  
   - Cloner le dépôt  
   - Installer les dépendances : `pip install flask scikit-learn pandas`  
   - Lancer : `python app.py`  
   - Ouvrir : `http://127.0.0.1:5000`

Cordialement.

## Auteur

Noura El Ghazouani — MSID — 2025/2026
