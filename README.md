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

Aucune installation requise. Il suffit d'ouvrir `index.html` dans un navigateur web.

## Auteur

Nom Prénom — M1 Data Science — 2025/2026
