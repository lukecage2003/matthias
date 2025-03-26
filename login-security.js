// Module de sécurité pour les tentatives de connexion pour Tech Shield

// Configuration des règles de sécurité pour les connexions
const loginSecurityConfig = {
    // Nombre maximum de tentatives de connexion avant blocage temporaire
    maxLoginAttempts: 5,
    
    // Durée du blocage temporaire (en minutes)
    temporaryBlockDuration: 15,
    
    // Durée de la période d'observation pour les tentatives (en minutes)
    attemptWindowMinutes: 30,
    
    // Activer la vérification de l'agent utilisateur (User-Agent)
    checkUserAgent: true,
    
    // Activer la vérification de l'empreinte du navigateur
    checkBrowserFingerprint: true,
    
    // Activer la détection de changement de pays (basé sur l'IP)
    detectCountryChange: true,
    
    // Activer la détection d'utilisation de VPN/proxy
    detectVPN: true,
    
    // Activer la détection d'attaques par force brute
    detectBruteForce: true,
    
    // Seuil pour la détection d'attaque par force brute (tentatives par minute)
    bruteForceTreshold: 10
};

// Stockage des tentatives de connexion
const loginAttempts = {};

// Stockage des adresses IP bloquées temporairement
const blockedIPs = {};

// Stockage des empreintes de navigateur connues par utilisateur
const knownBrowsers = {};

// Fonction pour enregistrer une tentative de connexion
function recordLoginAttempt(email, ipAddress, userAgent, success) {
    const now = new Date();
    
    // Initialiser l'entrée si elle n'existe pas
    if (!loginAttempts[email]) {
        loginAttempts[email] = [];
    }
    
    // Ajouter la tentative
    loginAttempts[email].push({
        timestamp: now.toISOString(),
        ipAddress: ipAddress,
        userAgent: userAgent,
        success: success
    });
    
    // Nettoyer les anciennes tentatives
    cleanOldAttempts(email);
    
    // Vérifier si l'utilisateur doit être bloqué
    return checkForBlocking(email, ipAddress);
}

// Fonction pour nettoyer les anciennes tentatives
function cleanOldAttempts(email) {
    if (!loginAttempts[email]) return;
    
    const cutoffTime = new Date();
    cutoffTime.setMinutes(cutoffTime.getMinutes() - loginSecurityConfig.attemptWindowMinutes);
    
    loginAttempts[email] = loginAttempts[email].filter(attempt => 
        new Date(attempt.timestamp) >= cutoffTime
    );
}

// Fonction pour vérifier si un utilisateur ou une IP doit être bloqué
function checkForBlocking(email, ipAddress) {
    // Vérifier si l'IP est déjà bloquée
    const ipBlockStatus = isIPBlocked(ipAddress);
    if (ipBlockStatus.blocked) {
        return ipBlockStatus;
    }
    
    // Vérifier le nombre de tentatives échouées récentes
    if (!loginAttempts[email]) return { blocked: false };
    
    const failedAttempts = loginAttempts[email].filter(attempt => !attempt.success);
    
    if (failedAttempts.length >= loginSecurityConfig.maxLoginAttempts) {
        // Bloquer l'IP
        blockIP(ipAddress);
        
        // Calculer le temps restant du blocage
        const blockExpiryTime = new Date();
        blockExpiryTime.setMinutes(blockExpiryTime.getMinutes() + loginSecurityConfig.temporaryBlockDuration);
        
        return { 
            blocked: true, 
            reason: 'Trop de tentatives de connexion échouées', 
            expiresAt: blockExpiryTime.toISOString(),
            remainingMinutes: loginSecurityConfig.temporaryBlockDuration
        };
    }
    
    return { blocked: false };
}

// Fonction pour bloquer temporairement une adresse IP
function blockIP(ipAddress) {
    const expiryTime = new Date();
    expiryTime.setMinutes(expiryTime.getMinutes() + loginSecurityConfig.temporaryBlockDuration);
    
    blockedIPs[ipAddress] = expiryTime.toISOString();
    
    // Enregistrer le blocage dans les logs si disponible
    if (window.securityLogs) {
        window.securityLogs.addLoginLog('système', ipAddress, window.securityLogs.LOG_TYPES.WARNING, 
            `IP bloquée temporairement pour ${loginSecurityConfig.temporaryBlockDuration} minutes suite à trop de tentatives échouées`);
    }
    
    return true;
}

// Fonction pour vérifier si une IP est bloquée
function isIPBlocked(ipAddress) {
    if (blockedIPs[ipAddress]) {
        const blockExpiryTime = new Date(blockedIPs[ipAddress]);
        const now = new Date();
        
        if (now < blockExpiryTime) {
            // Calculer le temps restant en minutes
            const remainingMs = blockExpiryTime - now;
            const remainingMinutes = Math.ceil(remainingMs / (60 * 1000));
            
            return { 
                blocked: true, 
                reason: 'Adresse IP temporairement bloquée', 
                expiresAt: blockedIPs[ipAddress],
                remainingMinutes: remainingMinutes
            };
        } else {
            // Le blocage a expiré, supprimer l'entrée
            delete blockedIPs[ipAddress];
        }
    }
    
    return { blocked: false };
}

// Fonction pour détecter une attaque par force brute
function detectBruteForceAttack(ipAddress) {
    if (!loginSecurityConfig.detectBruteForce) return false;
    
    // Compter les tentatives de connexion depuis cette IP dans la dernière minute
    const cutoffTime = new Date();
    cutoffTime.setMinutes(cutoffTime.getMinutes() - 1);
    
    let recentAttempts = 0;
    
    // Parcourir toutes les tentatives de tous les utilisateurs
    for (const email in loginAttempts) {
        recentAttempts += loginAttempts[email].filter(attempt => 
            attempt.ipAddress === ipAddress && 
            new Date(attempt.timestamp) >= cutoffTime
        ).length;
    }
    
    // Vérifier si le nombre de tentatives dépasse le seuil
    if (recentAttempts >= loginSecurityConfig.bruteForceTreshold) {
        // Bloquer l'IP pour une durée plus longue en cas d'attaque par force brute
        const expiryTime = new Date();
        expiryTime.setMinutes(expiryTime.getMinutes() + loginSecurityConfig.temporaryBlockDuration * 2);
        
        blockedIPs[ipAddress] = expiryTime.toISOString();
        
        // Enregistrer l'attaque dans les logs si disponible
        if (window.securityLogs) {
            window.securityLogs.addLoginLog('système', ipAddress, window.securityLogs.LOG_TYPES.CRITICAL, 
                `Attaque par force brute détectée (${recentAttempts} tentatives en 1 minute). IP bloquée pour ${loginSecurityConfig.temporaryBlockDuration * 2} minutes.`);
        }
        
        return true;
    }
    
    return false;
}

// Fonction pour vérifier si une connexion est suspecte (changement d'appareil, de localisation, etc.)
function isLoginSuspicious(email, ipAddress, userAgent) {
    // Si c'est la première connexion de l'utilisateur, enregistrer l'appareil et retourner false
    if (!knownBrowsers[email]) {
        knownBrowsers[email] = [{
            ipAddress: ipAddress,
            userAgent: userAgent,
            firstSeen: new Date().toISOString(),
            lastSeen: new Date().toISOString()
        }];
        return false;
    }
    
    // Vérifier si l'appareil est connu
    const knownDevice = knownBrowsers[email].find(device => 
        device.userAgent === userAgent
    );
    
    if (knownDevice) {
        // Mettre à jour la date de dernière utilisation
        knownDevice.lastSeen = new Date().toISOString();
        
        // Vérifier si l'IP a changé (possible changement de localisation)
        if (loginSecurityConfig.detectCountryChange && knownDevice.ipAddress !== ipAddress) {
            // Dans un environnement réel, on vérifierait ici si le pays associé à l'IP a changé
            // Pour cette démonstration, on considère simplement que l'IP a changé
            
            // Mettre à jour l'IP
            knownDevice.ipAddress = ipAddress;
            
            // Enregistrer le changement dans les logs si disponible
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(email, ipAddress, window.securityLogs.LOG_TYPES.SUSPICIOUS, 
                    `Connexion depuis une nouvelle adresse IP (${ipAddress})`);
            }
            
            return true;
        }
        
        return false;
    } else {
        // Nouvel appareil détecté
        knownBrowsers[email].push({
            ipAddress: ipAddress,
            userAgent: userAgent,
            firstSeen: new Date().toISOString(),
            lastSeen: new Date().toISOString()
        });
        
        // Enregistrer le nouvel appareil dans les logs si disponible
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(email, ipAddress, window.securityLogs.LOG_TYPES.SUSPICIOUS, 
                `Connexion depuis un nouvel appareil (${userAgent})`);
        }
        
        return true;
    }
}

// Fonction pour obtenir les statistiques de connexion d'un utilisateur
function getUserLoginStats(email) {
    if (!loginAttempts[email]) {
        return {
            totalAttempts: 0,
            successfulAttempts: 0,
            failedAttempts: 0,
            knownDevices: knownBrowsers[email] ? knownBrowsers[email].length : 0,
            lastAttempt: null
        };
    }
    
    const attempts = loginAttempts[email];
    const successfulAttempts = attempts.filter(attempt => attempt.success).length;
    
    return {
        totalAttempts: attempts.length,
        successfulAttempts: successfulAttempts,
        failedAttempts: attempts.length - successfulAttempts,
        knownDevices: knownBrowsers[email] ? knownBrowsers[email].length : 0,
        lastAttempt: attempts.length > 0 ? attempts[attempts.length - 1] : null
    };
}

// Fonction pour réinitialiser les tentatives de connexion d'un utilisateur
function resetUserLoginAttempts(email) {
    if (loginAttempts[email]) {
        loginAttempts[email] = [];
        return true;
    }
    return false;
}

// Fonction pour débloquer une adresse IP
function unblockIP(ipAddress) {
    if (blockedIPs[ipAddress]) {
        delete blockedIPs[ipAddress];
        
        // Enregistrer le déblocage dans les logs si disponible
        if (window.securityLogs) {
            window.securityLogs.addLoginLog('système', ipAddress, window.securityLogs.LOG_TYPES.INFO, 
                `IP débloquée manuellement`);
        }
        
        return true;
    }
    return false;
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.loginSecurity = {
    recordLoginAttempt,
    isIPBlocked,
    detectBruteForceAttack,
    isLoginSuspicious,
    getUserLoginStats,
    resetUserLoginAttempts,
    blockIP,
    unblockIP,
    config: loginSecurityConfig
};