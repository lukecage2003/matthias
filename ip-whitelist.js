// Système de liste blanche d'adresses IP pour Tech Shield

// Importer la configuration si disponible
if (!window.ipWhitelistConfig) {
    console.warn('Configuration de liste blanche d\'IP non trouvée, utilisation des paramètres par défaut');
}

// Structure pour stocker les adresses IP autorisées
const ipWhitelist = [
    // Format: { ip: 'xxx.xxx.xxx.xxx', description: 'Description', addedBy: 'email', addedAt: 'timestamp', expiresAt: 'timestamp', permanent: boolean }
    { ip: '192.168.1.1', description: 'Bureau principal', addedBy: 'admin@techshield.com', addedAt: new Date().toISOString(), permanent: true },
    { ip: '10.0.0.1', description: 'Réseau VPN', addedBy: 'admin@techshield.com', addedAt: new Date().toISOString(), permanent: false }
];

// Stockage des tentatives d'accès échouées par IP
const failedAccessAttempts = {};

// Obtenir la configuration
function getConfig() {
    return window.ipWhitelistConfig || {
        enabled: true,
        strictMode: false,
        maxEntries: 50,
        entryValidityDays: 0,
        maxFailedAttempts: 5,
        temporaryBlockDuration: 30,
        reservedRanges: [],
        exceptions: [{ ip: '127.0.0.1', description: 'Localhost', permanent: true }]
    };
}

// Fonction pour obtenir l'adresse IP du client
function getClientIP() {
    // Dans un environnement réel, cette fonction obtiendrait l'IP du client depuis la requête HTTP
    // Pour cette démonstration, nous simulons une adresse IP
    return '192.168.1.1'; // IP simulée pour la démonstration
}

// Fonction pour convertir une adresse IP en nombre pour comparaison
function ipToNumber(ip) {
    const parts = ip.split('.');
    return ((parseInt(parts[0], 10) << 24) |
            (parseInt(parts[1], 10) << 16) |
            (parseInt(parts[2], 10) << 8) |
            parseInt(parts[3], 10)) >>> 0;
}

// Fonction pour vérifier si une IP est dans une plage réservée
function isIPInReservedRange(ipAddress) {
    const config = getConfig();
    if (!config.reservedRanges || config.reservedRanges.length === 0) {
        return false;
    }
    
    const ipNum = ipToNumber(ipAddress);
    
    return config.reservedRanges.some(range => {
        const startNum = ipToNumber(range.start);
        const endNum = ipToNumber(range.end);
        return ipNum >= startNum && ipNum <= endNum;
    });
}

// Fonction pour vérifier si une adresse IP est dans la liste blanche
function isIPWhitelisted(ipAddress) {
    // Vérifier d'abord les exceptions (toujours autorisées)
    const config = getConfig();
    if (config.exceptions && config.exceptions.some(entry => entry.ip === ipAddress)) {
        return true;
    }
    
    // Nettoyer les entrées expirées
    cleanExpiredEntries();
    
    return ipWhitelist.some(entry => entry.ip === ipAddress);
}

// Fonction pour nettoyer les entrées expirées
function cleanExpiredEntries() {
    const config = getConfig();
    if (!config.entryValidityDays) return;
    
    const now = new Date();
    
    // Filtrer les entrées expirées
    for (let i = ipWhitelist.length - 1; i >= 0; i--) {
        const entry = ipWhitelist[i];
        
        // Ne pas supprimer les entrées permanentes
        if (entry.permanent) continue;
        
        // Vérifier si l'entrée a une date d'expiration
        if (entry.expiresAt) {
            if (new Date(entry.expiresAt) < now) {
                ipWhitelist.splice(i, 1);
            }
        } else if (config.entryValidityDays > 0) {
            // Calculer la date d'expiration pour les anciennes entrées
            const addedAt = new Date(entry.addedAt);
            const expiryDate = new Date(addedAt);
            expiryDate.setDate(expiryDate.getDate() + config.entryValidityDays);
            
            if (expiryDate < now) {
                ipWhitelist.splice(i, 1);
            } else {
                // Mettre à jour l'entrée avec la date d'expiration
                entry.expiresAt = expiryDate.toISOString();
            }
        }
    }
    
    // Sauvegarder les modifications
    saveWhitelistToStorage();
}

// Fonction pour ajouter une adresse IP à la liste blanche
function addToWhitelist(ipAddress, description, addedBy, permanent = false) {
    const config = getConfig();
    
    // Vérifier si la fonctionnalité est activée
    if (!config.enabled) {
        return { success: false, reason: 'La liste blanche d\'IP est désactivée' };
    }
    
    // Vérifier si l'IP est déjà dans la liste
    if (isIPWhitelisted(ipAddress)) {
        return { success: false, reason: 'Cette adresse IP est déjà dans la liste blanche' };
    }
    
    // Vérifier si l'IP est dans une plage réservée
    if (isIPInReservedRange(ipAddress) && !permanent) {
        return { success: false, reason: 'Cette adresse IP est dans une plage réservée' };
    }
    
    // Vérifier si la liste a atteint sa capacité maximale
    if (ipWhitelist.length >= config.maxEntries) {
        return { success: false, reason: 'La liste blanche a atteint sa capacité maximale' };
    }
    
    // Calculer la date d'expiration si nécessaire
    let expiresAt = null;
    if (!permanent && config.entryValidityDays > 0) {
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + config.entryValidityDays);
        expiresAt = expiryDate.toISOString();
    }
    
    // Ajouter l'IP à la liste blanche
    ipWhitelist.push({
        ip: ipAddress,
        description: description,
        addedBy: addedBy,
        addedAt: new Date().toISOString(),
        expiresAt: expiresAt,
        permanent: permanent
    });
    
    // Sauvegarder la liste dans le localStorage
    saveWhitelistToStorage();
    
    return { 
        success: true, 
        expiresAt: expiresAt,
        permanent: permanent
    };
}

// Fonction pour supprimer une adresse IP de la liste blanche
function removeFromWhitelist(ipAddress) {
    const initialLength = ipWhitelist.length;
    
    // Filtrer la liste pour supprimer l'IP spécifiée
    const newWhitelist = ipWhitelist.filter(entry => entry.ip !== ipAddress);
    
    // Mettre à jour la liste
    ipWhitelist.length = 0;
    newWhitelist.forEach(entry => ipWhitelist.push(entry));
    
    // Sauvegarder la liste dans le localStorage
    saveWhitelistToStorage();
    
    // Retourner true si une IP a été supprimée
    return initialLength > ipWhitelist.length;
}

// Fonction pour obtenir toutes les adresses IP de la liste blanche
function getAllWhitelistedIPs() {
    // Charger la liste depuis le localStorage
    loadWhitelistFromStorage();
    return ipWhitelist;
}

// Fonction pour sauvegarder la liste blanche dans le localStorage
function saveWhitelistToStorage() {
    localStorage.setItem('ipWhitelist', JSON.stringify(ipWhitelist));
}

// Fonction pour charger la liste blanche depuis le localStorage
function loadWhitelistFromStorage() {
    const storedWhitelist = localStorage.getItem('ipWhitelist');
    if (storedWhitelist) {
        // Fusionner la liste stockée avec la liste actuelle
        const parsedWhitelist = JSON.parse(storedWhitelist);
        
        // Vider le tableau actuel et ajouter les entrées stockées
        ipWhitelist.length = 0;
        parsedWhitelist.forEach(entry => ipWhitelist.push(entry));
    }
}

// Fonction pour vérifier si une IP est temporairement bloquée
function isIPTemporarilyBlocked(ipAddress) {
    if (!failedAccessAttempts[ipAddress]) {
        return false;
    }
    
    const config = getConfig();
    const attempts = failedAccessAttempts[ipAddress];
    
    // Vérifier si le nombre de tentatives a dépassé le seuil
    if (attempts.count >= config.maxFailedAttempts) {
        const blockExpiryTime = new Date(attempts.lastAttempt);
        blockExpiryTime.setMinutes(blockExpiryTime.getMinutes() + config.temporaryBlockDuration);
        
        // Vérifier si le blocage est toujours actif
        if (new Date() < blockExpiryTime) {
            return {
                blocked: true,
                expiresAt: blockExpiryTime.toISOString(),
                remainingMinutes: Math.ceil((blockExpiryTime - new Date()) / (60 * 1000))
            };
        } else {
            // Réinitialiser le compteur si le blocage a expiré
            resetFailedAttempts(ipAddress);
            return false;
        }
    }
    
    return false;
}

// Fonction pour enregistrer une tentative d'accès échouée
function recordFailedAttempt(ipAddress) {
    if (!failedAccessAttempts[ipAddress]) {
        failedAccessAttempts[ipAddress] = {
            count: 0,
            firstAttempt: new Date().toISOString(),
            lastAttempt: new Date().toISOString()
        };
    }
    
    failedAccessAttempts[ipAddress].count += 1;
    failedAccessAttempts[ipAddress].lastAttempt = new Date().toISOString();
    
    return failedAccessAttempts[ipAddress];
}

// Fonction pour réinitialiser le compteur de tentatives échouées
function resetFailedAttempts(ipAddress) {
    if (failedAccessAttempts[ipAddress]) {
        delete failedAccessAttempts[ipAddress];
        return true;
    }
    return false;
}

// Fonction pour vérifier l'accès basé sur l'IP
function checkIPAccess() {
    const config = getConfig();
    const clientIP = getClientIP();
    
    // Vérifier si la fonctionnalité est activée
    if (!config.enabled) {
        return { allowed: true, clientIP: clientIP };
    }
    
    // Vérifier si l'IP est temporairement bloquée
    const blockStatus = isIPTemporarilyBlocked(clientIP);
    if (blockStatus) {
        // Enregistrer la tentative dans les logs si disponible
        if (window.securityLogs) {
            window.securityLogs.addLoginLog('système', clientIP, window.securityLogs.LOG_TYPES.WARNING, 
                `Tentative d'accès depuis une IP temporairement bloquée. Déblocage dans ${blockStatus.remainingMinutes} minutes.`);
        }
        
        return {
            allowed: false,
            clientIP: clientIP,
            reason: 'IP temporairement bloquée',
            blockStatus: blockStatus
        };
    }
    
    // Vérifier si l'IP est dans la liste blanche
    const isWhitelisted = isIPWhitelisted(clientIP);
    
    // En mode strict, toutes les IP non listées sont bloquées
    if (config.strictMode && !isWhitelisted) {
        // Enregistrer la tentative échouée
        const attemptStatus = recordFailedAttempt(clientIP);
        
        // Enregistrer la tentative dans les logs si disponible
        if (window.securityLogs) {
            window.securityLogs.addLoginLog('système', clientIP, window.securityLogs.LOG_TYPES.SUSPICIOUS, 
                `Tentative d'accès depuis une IP non autorisée (${attemptStatus.count}/${config.maxFailedAttempts})`);
            
            // Vérifier si l'IP doit être bloquée
            if (attemptStatus.count >= config.maxFailedAttempts) {
                window.securityLogs.addLoginLog('système', clientIP, window.securityLogs.LOG_TYPES.WARNING, 
                    `IP bloquée temporairement pour ${config.temporaryBlockDuration} minutes après ${config.maxFailedAttempts} tentatives échouées`);
            }
        }
        
        return {
            allowed: false,
            clientIP: clientIP,
            reason: 'IP non autorisée en mode strict',
            attemptStatus: attemptStatus
        };
    }
    
    // Si l'IP est autorisée, réinitialiser le compteur de tentatives
    resetFailedAttempts(clientIP);
    
    return {
        allowed: true,
        clientIP: clientIP,
        whitelisted: isWhitelisted
    };
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.ipWhitelist = {
    // Fonctions de base
    getClientIP,
    isIPWhitelisted,
    addToWhitelist,
    removeFromWhitelist,
    getAllWhitelistedIPs,
    checkIPAccess,
    
    // Fonctions avancées
    getConfig,
    isIPInReservedRange,
    isIPTemporarilyBlocked,
    recordFailedAttempt,
    resetFailedAttempts,
    cleanExpiredEntries,
    
    // Constantes
    LOG_TYPES: {
        ACCESS_ALLOWED: 'access_allowed',
        ACCESS_DENIED: 'access_denied',
        IP_BLOCKED: 'ip_blocked',
        IP_ADDED: 'ip_added',
        IP_REMOVED: 'ip_removed'
    }
};