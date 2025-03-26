// Système d'authentification à deux facteurs (2FA) pour Tech Shield

// Simuler une base de données pour stocker les secrets TOTP des utilisateurs
const twoFASecrets = {
    // Format: email: { secret: 'SECRET_KEY', enabled: true/false }
    "admin@techshield.com": { secret: "JBSWY3DPEHPK3PXP", enabled: false }
};

// Fonction pour générer un code TOTP (Time-based One-Time Password)
function generateTOTP(secret) {
    // Dans un environnement réel, cette fonction utiliserait une bibliothèque comme 'otplib'
    // Pour cette démonstration, nous simulons la génération d'un code à 6 chiffres
    
    // Obtenir le temps actuel en secondes et le diviser par 30 (période standard TOTP)
    const timeStep = 30;
    const timeCounter = Math.floor(Date.now() / 1000 / timeStep);
    
    // Utiliser une fonction de hachage simple pour simuler la génération du code
    // Dans un environnement réel, cela utiliserait HMAC-SHA1
    let code = (parseInt(secret.substring(0, 8), 36) ^ timeCounter) % 1000000;
    
    // S'assurer que le code a 6 chiffres en ajoutant des zéros au début si nécessaire
    return code.toString().padStart(6, '0');
}

// Fonction pour vérifier un code TOTP
function verifyTOTP(email, code) {
    // Vérifier si l'utilisateur a configuré 2FA
    if (!twoFASecrets[email] || !twoFASecrets[email].enabled) {
        return false;
    }
    
    const secret = twoFASecrets[email].secret;
    const expectedCode = generateTOTP(secret);
    
    // Vérifier si le code fourni correspond au code attendu
    return code === expectedCode;
}

// Fonction pour activer 2FA pour un utilisateur
function enableTwoFA(email, secret) {
    twoFASecrets[email] = { secret, enabled: true };
    return true;
}

// Fonction pour désactiver 2FA pour un utilisateur
function disableTwoFA(email) {
    if (twoFASecrets[email]) {
        twoFASecrets[email].enabled = false;
        return true;
    }
    return false;
}

// Fonction pour vérifier si 2FA est activé pour un utilisateur
function isTwoFAEnabled(email) {
    return twoFASecrets[email] && twoFASecrets[email].enabled;
}

// Fonction pour obtenir le secret TOTP d'un utilisateur
function getTwoFASecret(email) {
    if (twoFASecrets[email]) {
        return twoFASecrets[email].secret;
    }
    return null;
}

// Fonction pour générer un nouveau secret TOTP
function generateTwoFASecret() {
    // Dans un environnement réel, cela utiliserait une bibliothèque comme 'otplib'
    // Pour cette démonstration, nous générons une chaîne aléatoire
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let secret = '';
    for (let i = 0; i < 16; i++) {
        secret += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return secret;
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.twoFA = {
    generateTOTP,
    verifyTOTP,
    enableTwoFA,
    disableTwoFA,
    isTwoFAEnabled,
    getTwoFASecret,
    generateTwoFASecret
};