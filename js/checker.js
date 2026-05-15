/**
 * checker.js — Logique d'analyse de mot de passe
 * Projet Sécurité Informatique — M1 Data Science
 * 2025/2026
 */

// =============================================
// Définition des critères de sécurité
// =============================================
const CRITERIA = {
  'c-len':     pwd => pwd.length >= 8,
  'c-upper':   pwd => /[A-Z]/.test(pwd),
  'c-lower':   pwd => /[a-z]/.test(pwd),
  'c-digit':   pwd => /[0-9]/.test(pwd),
  'c-special': pwd => /[^A-Za-z0-9]/.test(pwd),
  'c-long':    pwd => pwd.length >= 12,
};

// Couleurs et labels selon le score (0 à 6)
const STRENGTH_COLORS = ['#e53935', '#e53935', '#fb8c00', '#fdd835', '#43a047', '#1b5e20'];
const STRENGTH_LABELS = ['Très faible', 'Très faible', 'Faible', 'Moyen', 'Fort', 'Très fort'];

// =============================================
// Estimation du temps de crackage (brute-force)
// =============================================
function estimateCrackTime(pwd) {
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pwd)) pool += 32;
  if (pool === 0 || pwd.length === 0) return null;

  // Nombre de combinaisons possibles
  const combinations = Math.pow(pool, pwd.length);

  // Vitesse d'attaque : 10 milliards de tentatives/seconde (GPU)
  const attemptsPerSecond = 1e10;
  const seconds = combinations / attemptsPerSecond;

  if (seconds < 1)           return 'moins d\'une seconde ⚠️';
  if (seconds < 60)          return Math.round(seconds) + ' secondes';
  if (seconds < 3600)        return Math.round(seconds / 60) + ' minutes';
  if (seconds < 86400)       return Math.round(seconds / 3600) + ' heures';
  if (seconds < 31536000)    return Math.round(seconds / 86400) + ' jours';
  if (seconds < 3.15e9)      return Math.round(seconds / 31536000) + ' ans';
  return 'des milliards d\'années ✅';
}

// =============================================
// Fonction principale d'analyse
// =============================================
function analyzePassword(pwd) {
  let score = 0;

  // Vérifie chaque critère et met à jour l'interface
  for (const [id, check] of Object.entries(CRITERIA)) {
    const el = document.getElementById(id);
    if (check(pwd)) {
      el.classList.add('ok');
      score++;
    } else {
      el.classList.remove('ok');
    }
  }

  // Met à jour la barre de force
  const bar   = document.getElementById('strengthBar');
  const label = document.getElementById('strengthLabel');

  if (pwd.length === 0) {
    bar.style.width      = '0%';
    bar.style.background = '';
    label.textContent    = '— Entrez un mot de passe';
    label.style.color    = '#888';
  } else {
    const pct  = Math.round((score / 6) * 100);
    bar.style.width      = Math.max(pct, 10) + '%';
    bar.style.background = STRENGTH_COLORS[score];
    label.textContent    = STRENGTH_LABELS[score];
    label.style.color    = STRENGTH_COLORS[score];
  }

  // Met à jour le temps de crackage
  const crackCard = document.getElementById('crackCard');
  const crackTime = document.getElementById('crackTime');

  if (pwd.length > 0) {
    crackCard.style.display = 'block';
    crackTime.textContent   = estimateCrackTime(pwd);
  } else {
    crackCard.style.display = 'none';
  }
}

// =============================================
// Afficher / masquer le mot de passe
// =============================================
function toggleVisibility() {
  const input = document.getElementById('pwdInput');
  const btn   = document.getElementById('visBtn');

  if (input.type === 'password') {
    input.type    = 'text';
    btn.textContent = '🙈';
  } else {
    input.type    = 'password';
    btn.textContent = '👁';
  }
}
