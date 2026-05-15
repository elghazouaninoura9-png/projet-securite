"""
app.py — Serveur web Flask pour le Phishing URL Detector

Lance le serveur avec : python app.py
Puis ouvre : http://127.0.0.1:5000
"""

import re
import pickle
import numpy as np
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ============================================================
# CHARGEMENT DU MODÈLE
# ============================================================

try:
    with open('model.pkl', 'rb') as f:
        data = pickle.load(f)
    model         = data['model']
    feature_names = data['feature_names']
    model_accuracy = data['accuracy']
    print(f"Modèle chargé — Précision : {model_accuracy * 100:.1f}%")
except FileNotFoundError:
    print("ERREUR : model.pkl introuvable. Lancez d'abord train_model.py")
    model = None

# ============================================================
# FEATURE EXTRACTION (identique à train_model.py)
# ============================================================

SUSPICIOUS_WORDS = ['login', 'verify', 'secure', 'account', 'update',
                    'banking', 'confirm', 'signin', 'alert', 'suspended',
                    'blocked', 'urgent', 'free', 'winner', 'prize']

SUSPICIOUS_TLDS  = ['.tk', '.ml', '.ru', '.xyz', '.gq', '.cf', '.ga']

BRANDS = ['paypal', 'amazon', 'google', 'facebook', 'apple',
          'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin']

LEGIT_DOMAINS = ['google.com', 'facebook.com', 'amazon.fr', 'amazon.com',
                 'paypal.com', 'apple.com', 'microsoft.com', 'netflix.com']

def extract_features(url):
    features = {}
    try:
        domain = re.findall(r'://([^/]+)', url)[0]
    except:
        domain = url

    features['url_length']               = len(url)
    features['domain_length']            = len(domain)
    features['nb_subdomains']            = domain.count('.') - 1
    features['has_ip']                   = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at_symbol']            = 1 if '@' in url else 0
    features['nb_dashes']                = domain.count('-')
    features['is_https']                 = 1 if url.startswith('https') else 0
    features['nb_digits']                = sum(c.isdigit() for c in url)
    features['nb_suspicious_words']      = sum(1 for w in SUSPICIOUS_WORDS if w in url.lower())
    try:
        path = url.split('/', 3)[3] if len(url.split('/', 3)) > 3 else ''
    except:
        path = ''
    features['path_length']              = len(path)
    features['nb_params']                = url.count('?') + url.count('&')
    features['has_suspicious_tld']       = 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0
    is_legit = any(ld in url for ld in LEGIT_DOMAINS)
    features['brand_in_suspicious_domain'] = 1 if (
        any(b in domain.lower() for b in BRANDS) and not is_legit
    ) else 0
    features['nb_slashes']               = url.count('/')
    features['path_depth']               = url.count('/') - 2

    return list(features.values()), features

# ============================================================
# ROUTES FLASK
# ============================================================

@app.route('/')
def index():
    return render_template('index.html',
                           accuracy=round(model_accuracy * 100, 1) if model else 0)


@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Modèle non chargé. Lancez train_model.py d\'abord.'}), 500

    data = request.get_json()
    url  = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL vide'}), 400

    # Ajout automatique du protocole si absent
    if not url.startswith('http'):
        url = 'http://' + url

    # Extraction des features
    feat_array, feat_dict = extract_features(url)
    X = np.array([feat_array])

    # Prédiction
    prediction   = model.predict(X)[0]
    proba        = model.predict_proba(X)[0]
    confidence   = round(float(max(proba)) * 100, 1)

    # Indices de risque pour l'explication
    risk_flags = []
    if feat_dict['has_ip']:
        risk_flags.append("Adresse IP dans l'URL (pas de nom de domaine)")
    if feat_dict['has_at_symbol']:
        risk_flags.append("Présence du symbole @ (redirection trompeuse)")
    if not feat_dict['is_https']:
        risk_flags.append("Pas de HTTPS (connexion non chiffrée)")
    if feat_dict['has_suspicious_tld']:
        risk_flags.append("Extension de domaine suspecte (.tk, .ml, .ru, .xyz...)")
    if feat_dict['brand_in_suspicious_domain']:
        risk_flags.append("Marque connue imitée dans un domaine suspect")
    if feat_dict['nb_suspicious_words'] >= 2:
        risk_flags.append(f"{feat_dict['nb_suspicious_words']} mots suspects détectés (login, verify, secure...)")
    if feat_dict['nb_dashes'] >= 2:
        risk_flags.append(f"{feat_dict['nb_dashes']} tirets dans le domaine")
    if feat_dict['url_length'] > 75:
        risk_flags.append(f"URL très longue ({feat_dict['url_length']} caractères)")
    if feat_dict['nb_subdomains'] >= 3:
        risk_flags.append(f"Trop de sous-domaines ({feat_dict['nb_subdomains']})")

    # Feature importances pour l'affichage
    importances = model.feature_importances_
    top_features = sorted(
        zip(feature_names, feat_array, importances),
        key=lambda x: -x[2]
    )[:6]

    return jsonify({
        'url':        url,
        'prediction': int(prediction),
        'label':      'Phishing' if prediction == 1 else 'Légitime',
        'confidence': confidence,
        'risk_flags': risk_flags,
        'features':   [
            {
                'name':       f[0],
                'value':      round(float(f[1]), 2),
                'importance': round(float(f[2]) * 100, 1)
            }
            for f in top_features
        ]
    })


if __name__ == '__main__':
    print("Serveur démarré sur http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
