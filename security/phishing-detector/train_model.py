"""
train_model.py — Entraînement du modèle ML de détection de phishing

Ce script :
1. Génère un dataset d'URLs légitimes et de phishing
2. Extrait des features (caractéristiques) de chaque URL
3. Entraîne un modèle Random Forest
4. Sauvegarde le modèle dans model.pkl
"""

import re
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ============================================================
# 1. DATASET — URLs légitimes (0) et phishing (1)
# ============================================================

legitimate_urls = [
    "https://www.google.com",
    "https://www.facebook.com/login",
    "https://github.com/user/repo",
    "https://www.amazon.fr/products",
    "https://www.youtube.com/watch?v=abc123",
    "https://stackoverflow.com/questions/12345",
    "https://www.wikipedia.org/wiki/Python",
    "https://mail.google.com/mail/u/0/",
    "https://www.linkedin.com/in/username",
    "https://docs.python.org/3/library/",
    "https://www.apple.com/iphone",
    "https://www.microsoft.com/fr-fr/windows",
    "https://www.netflix.com/browse",
    "https://www.twitter.com/home",
    "https://www.instagram.com/explore",
    "https://www.reddit.com/r/python",
    "https://www.airbnb.com/rooms/12345",
    "https://www.booking.com/hotel/fr",
    "https://www.paypal.com/myaccount",
    "https://www.ebay.fr/itm/product",
    "https://portal.azure.com",
    "https://console.aws.amazon.com",
    "https://www.orange.fr/portail",
    "https://www.sfr.fr/mon-espace",
    "https://www.gouvernement.fr/actualite",
    "https://www.service-public.fr/particuliers",
    "https://impots.gouv.fr/portail/accueil",
    "https://www.banque-france.fr",
    "https://www.caf.fr/mon-compte",
    "https://www.ameli.fr/assure",
]

phishing_urls = [
    "http://paypal-secure-login.verify-account.com/signin",
    "http://www.amazon-account-alert.com/login?user=victim",
    "http://secure-facebook.com-login.phishing.net/auth",
    "http://192.168.1.1/paypal/update-billing",
    "http://apple-id-verify.suspicious-domain.ru/account",
    "http://google-login.phishing-site.tk/accounts",
    "http://microsoft-support-alert.xyz/update-now",
    "http://netflix-payment-failed.suspicious.ml/billing",
    "http://bank-secure-verify.free.fr/login@user",
    "http://account-suspended-verify.com/amazon/signin",
    "http://www.go0gle.com/accounts/login-verify",
    "http://faceb00k-security.com/checkpoint/block",
    "http://paypa1.com-secure.login.verify.tk/account",
    "http://amaz0n.fr-account-verify.com/ap/signin",
    "http://secure-bankofamerica-alert.phishing.ml",
    "http://update-your-info.suspicious-bank.com/login",
    "http://verify-account-now.phishing.xyz/facebook",
    "http://steal-credentials.bad-domain.ru/google",
    "http://win-prize-now.scam-site.tk/congratulations",
    "http://your-account-blocked.phish.ml/verify@now",
    "http://12.34.56.78/paypal/secure/login.php",
    "http://10.0.0.1/bank-account/verify-credentials",
    "http://free-gift-card-winner.scam.tk/claim-now",
    "http://urgent-security-alert.phishing.com/apple-id",
    "http://account-verify-now.suspicious.xyz/signin",
    "http://confirm-identity.phishing-bank.ml/account",
    "http://you-won-iphone.fake-promo.tk/claim",
    "http://emergency-password-reset.phish.ru/google",
    "http://credit-card-expired.scam-alert.xyz/renew",
    "http://login-secure.fake-paypal.suspicious.net/auth",
]

# ============================================================
# 2. FEATURE EXTRACTION — Extraction des caractéristiques
# ============================================================

def extract_features(url):
    """
    Extrait 15 features (caractéristiques) d'une URL.
    Ces features sont utilisées par le modèle ML pour la classification.
    """
    features = {}

    # Feature 1 : Longueur totale de l'URL
    features['url_length'] = len(url)

    # Feature 2 : Longueur du domaine
    try:
        domain = re.findall(r'://([^/]+)', url)[0]
    except:
        domain = url
    features['domain_length'] = len(domain)

    # Feature 3 : Nombre de sous-domaines (points dans le domaine)
    features['nb_subdomains'] = domain.count('.') - 1

    # Feature 4 : Présence d'une adresse IP dans l'URL
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0

    # Feature 5 : Présence du symbole @ (redirection trompeuse)
    features['has_at_symbol'] = 1 if '@' in url else 0

    # Feature 6 : Présence de tirets dans le domaine (souvent utilisé dans le phishing)
    features['nb_dashes'] = domain.count('-')

    # Feature 7 : Utilisation de HTTPS (protocole sécurisé)
    features['is_https'] = 1 if url.startswith('https') else 0

    # Feature 8 : Nombre de chiffres dans l'URL
    features['nb_digits'] = sum(c.isdigit() for c in url)

    # Feature 9 : Présence de mots suspects dans l'URL
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update',
                        'banking', 'confirm', 'signin', 'alert', 'suspended',
                        'blocked', 'urgent', 'free', 'winner', 'prize']
    features['nb_suspicious_words'] = sum(1 for w in suspicious_words if w in url.lower())

    # Feature 10 : Longueur du chemin (path) de l'URL
    try:
        path = url.split('/', 3)[3] if len(url.split('/', 3)) > 3 else ''
    except:
        path = ''
    features['path_length'] = len(path)

    # Feature 11 : Nombre de paramètres dans l'URL (?)
    features['nb_params'] = url.count('?') + url.count('&')

    # Feature 12 : Extension de domaine suspecte (.tk, .ml, .ru, .xyz...)
    suspicious_tlds = ['.tk', '.ml', '.ru', '.xyz', '.gq', '.cf', '.ga']
    features['has_suspicious_tld'] = 1 if any(domain.endswith(t) for t in suspicious_tlds) else 0

    # Feature 13 : Présence de marques connues dans un domaine suspect
    brands = ['paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
              'netflix', 'instagram', 'twitter', 'linkedin']
    domain_lower = domain.lower()
    legit_domains = ['google.com', 'facebook.com', 'amazon.fr', 'amazon.com',
                     'paypal.com', 'apple.com', 'microsoft.com', 'netflix.com']
    is_legit = any(ld in url for ld in legit_domains)
    features['brand_in_suspicious_domain'] = 1 if (
        any(b in domain_lower for b in brands) and not is_legit
    ) else 0

    # Feature 14 : Nombre de slashes dans l'URL
    features['nb_slashes'] = url.count('/')

    # Feature 15 : Profondeur du chemin URL
    features['path_depth'] = url.count('/') - 2

    return list(features.values())

FEATURE_NAMES = [
    'url_length', 'domain_length', 'nb_subdomains', 'has_ip',
    'has_at_symbol', 'nb_dashes', 'is_https', 'nb_digits',
    'nb_suspicious_words', 'path_length', 'nb_params',
    'has_suspicious_tld', 'brand_in_suspicious_domain',
    'nb_slashes', 'path_depth'
]

# ============================================================
# 3. PRÉPARATION DU DATASET
# ============================================================

print("Préparation du dataset...")

all_urls = legitimate_urls + phishing_urls
labels   = [0] * len(legitimate_urls) + [1] * len(phishing_urls)

X = np.array([extract_features(url) for url in all_urls])
y = np.array(labels)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"  Dataset : {len(all_urls)} URLs ({len(legitimate_urls)} légitimes, {len(phishing_urls)} phishing)")
print(f"  Entraînement : {len(X_train)} | Test : {len(X_test)}")

# ============================================================
# 4. ENTRAÎNEMENT DU MODÈLE — Random Forest
# ============================================================

print("\nEntraînement du Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,   # 100 arbres de décision
    max_depth=10,       # Profondeur maximale de chaque arbre
    random_state=42
)
model.fit(X_train, y_train)

# ============================================================
# 5. ÉVALUATION DU MODÈLE
# ============================================================

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nPrécision du modèle : {accuracy * 100:.1f}%")
print("\nRapport de classification :")
print(classification_report(y_test, y_pred, target_names=['Légitime', 'Phishing']))

# Feature importance (pour le rapport)
print("\nImportance des features :")
importances = model.feature_importances_
for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1]):
    print(f"  {name:<35} : {imp:.3f}")

# ============================================================
# 6. SAUVEGARDE DU MODÈLE
# ============================================================

with open('model.pkl', 'wb') as f:
    pickle.dump({
        'model': model,
        'feature_names': FEATURE_NAMES,
        'accuracy': accuracy
    }, f)

print("\nModèle sauvegardé dans model.pkl")
print("Lancez maintenant : python app.py")
