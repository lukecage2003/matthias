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
    bruteForceTreshold: 10,
    
    // Système de blocage progressif
    enableProgressiveBlocking: true,
    
    // Facteur multiplicateur pour le temps de blocage progressif
    progressiveBlockingFactor: 2,
    
    // Durée maximale de blocage (en minutes)
    maxBlockDuration: 120,
    
    // Nombre de tentatives avant d'afficher un avertissement
    warningThreshold: 3,
    
    // Activer le stockage persistant des tentatives (localStorage)
    persistentStorage: true
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
    
    // Charger les tentatives depuis le localStorage si la persistance est activée
    if (loginSecurityConfig.persistentStorage) {
        loadLoginAttemptsFromStorage();
    }
    
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
    
    // Sauvegarder les tentatives dans le localStorage si la persistance est activée
    if (loginSecurityConfig.persistentStorage) {
        saveLoginAttemptsToStorage();
    }
    
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
    
    // Vérifier si l'utilisateur doit recevoir un avertissement
    if (failedAttempts.length >= loginSecurityConfig.warningThreshold && 
        failedAttempts.length < loginSecurityConfig.maxLoginAttempts) {
        const remainingAttempts = loginSecurityConfig.maxLoginAttempts - failedAttempts.length;
        
        return {
            blocked: false,
            warning: true,
            reason: `Attention: ${remainingAttempts} tentative(s) restante(s) avant blocage temporaire`,
            remainingAttempts: remainingAttempts
        };
    }
    
    if (failedAttempts.length >= loginSecurityConfig.maxLoginAttempts) {
        // Récupérer le nombre de tentatives précédentes pour cette IP
        let previousAttempts = 0;
        
        // Vérifier si cette IP a déjà été bloquée auparavant
        const previousBlockInfo = Object.entries(blockedIPs).find(([ip, info]) => ip === ipAddress);
        if (previousBlockInfo) {
            const blockInfo = previousBlockInfo[1];
            previousAttempts = typeof blockInfo === 'string' ? 1 : blockInfo.attempts;
        }
        
        // Bloquer l'IP avec le nombre de tentatives précédentes
        blockIP(ipAddress, previousAttempts);
        
        // Récupérer les informations de blocage mises à jour
        const updatedBlockStatus = isIPBlocked(ipAddress);
        
        return updatedBlockStatus;
    }
    
    return { blocked: false };
}

// Fonction pour bloquer temporairement une adresse IP
function blockIP(ipAddress, previousAttempts = 0) {
    // Calculer la durée du blocage en fonction du nombre de tentatives précédentes
    let blockDuration = loginSecurityConfig.temporaryBlockDuration;
    
    // Si le blocage progressif est activé, augmenter la durée en fonction des tentatives précédentes
    if (loginSecurityConfig.enableProgressiveBlocking && previousAttempts > 0) {
        // Augmenter la durée de blocage en fonction du facteur multiplicateur et du nombre de tentatives précédentes
        blockDuration = Math.min(
            loginSecurityConfig.temporaryBlockDuration * Math.pow(loginSecurityConfig.progressiveBlockingFactor, previousAttempts),
            loginSecurityConfig.maxBlockDuration
        );
    }
    
    const expiryTime = new Date();
    expiryTime.setMinutes(expiryTime.getMinutes() + blockDuration);
    
    // Stocker l'information de blocage avec le nombre de tentatives précédentes
    blockedIPs[ipAddress] = {
        expiresAt: expiryTime.toISOString(),
        attempts: previousAttempts + 1
    };
    
    // Enregistrer le blocage dans les logs si disponible
    if (window.securityLogs) {
        window.securityLogs.addLoginLog('système', ipAddress, window.securityLogs.LOG_TYPES.WARNING, 
            `IP bloquée temporairement pour ${blockDuration} minutes suite à trop de tentatives échouées`);
    }
    
    // Stocker les informations de blocage dans le localStorage si la persistance est activée
    if (loginSecurityConfig.persistentStorage) {
        saveBlockedIPsToStorage();
    }
    
    return true;
}

// Fonction pour vérifier si une IP est bloquée
function isIPBlocked(ipAddress) {
    // Charger les IPs bloquées depuis le localStorage si la persistance est activée
    if (loginSecurityConfig.persistentStorage) {
        loadBlockedIPsFromStorage();
    }
    
    if (blockedIPs[ipAddress]) {
        // Récupérer les informations de blocage
        const blockInfo = blockedIPs[ipAddress];
        const blockExpiryTime = new Date(typeof blockInfo === 'string' ? blockInfo : blockInfo.expiresAt);
        const now = new Date();
        
        if (now < blockExpiryTime) {
            // Calculer le temps restant en minutes
            const remainingMs = blockExpiryTime - now;
            const remainingMinutes = Math.ceil(remainingMs / (60 * 1000));
            
            // Récupérer le nombre de tentatives précédentes
            const attempts = typeof blockInfo === 'string' ? 1 : blockInfo.attempts;
            
            return { 
                blocked: true, 
                reason: 'Adresse IP temporairement bloquée', 
                expiresAt: typeof blockInfo === 'string' ? blockInfo : blockInfo.expiresAt,
                remainingMinutes: remainingMinutes,
                attempts: attempts
            };
        } else {
            // Le blocage a expiré, supprimer l'entrée
            delete blockedIPs[ipAddress];
            
            // Mettre à jour le localStorage si la persistance est activée
            if (loginSecurityConfig.persistentStorage) {
                saveBlockedIPsToStorage();
            }
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

// Fonction pour sauvegarder les IPs bloquées dans le localStorage
function saveBlockedIPsToStorage() {
    if (typeof localStorage !== 'undefined') {
        localStorage.setItem('blockedIPs', JSON.stringify(blockedIPs));
    }
}

// Fonction pour charger les IPs bloquées depuis le localStorage
function loadBlockedIPsFromStorage() {
    if (typeof localStorage !== 'undefined') {
        const storedBlockedIPs = localStorage.getItem('blockedIPs');
        if (storedBlockedIPs) {
            // Fusionner avec les IPs bloquées actuelles
            const parsedBlockedIPs = JSON.parse(storedBlockedIPs);
            Object.assign(blockedIPs, parsedBlockedIPs);
        }
    }
}

// Fonction pour sauvegarder les tentatives de connexion dans le localStorage
function saveLoginAttemptsToStorage() {
    if (typeof localStorage !== 'undefined') {
        localStorage.setItem('loginAttempts', JSON.stringify(loginAttempts));
    }
}

// Fonction pour charger les tentatives de connexion depuis le localStorage
function loadLoginAttemptsFromStorage() {
    if (typeof localStorage !== 'undefined') {
        const storedLoginAttempts = localStorage.getItem('loginAttempts');
        if (storedLoginAttempts) {
            // Fusionner avec les tentatives actuelles
            const parsedLoginAttempts = JSON.parse(storedLoginAttempts);
            Object.assign(loginAttempts, parsedLoginAttempts);
        }
    }
}

// Fonction pour obtenir le nombre de tentatives restantes avant blocage
function getRemainingAttempts(email) {
    if (!loginAttempts[email]) return loginSecurityConfig.maxLoginAttempts;
    
    const failedAttempts = loginAttempts[email].filter(attempt => !attempt.success).length;
    return Math.max(0, loginSecurityConfig.maxLoginAttempts - failedAttempts);
}

// Initialisation: charger les données depuis le localStorage si la persistance est activée
if (loginSecurityConfig.persistentStorage) {
    loadBlockedIPsFromStorage();
    loadLoginAttemptsFromStorage();
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
    getRemainingAttempts,
    saveBlockedIPsToStorage,
    loadBlockedIPsFromStorage,
    saveLoginAttemptsToStorage,
    loadLoginAttemptsFromStorage,
    config: loginSecurityConfig
};