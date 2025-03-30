// Module de journalisation de sécurité avancé pour Tech Shield

// Structure de données pour stocker les logs
let securityLogs = [];

// Types de logs disponibles
const LOG_TYPES = {
    SUCCESS: 'success',     // Connexion réussie
    FAILURE: 'failure',     // Échec de connexion
    SUSPICIOUS: 'suspicious', // Activité suspecte
    WARNING: 'warning',     // Avertissement
    INFO: 'info',           // Information
    CRITICAL: 'critical'    // Alerte critique
};

// Configuration des alertes de sécurité
const securityAlertConfig = {
    // Seuils d'alerte
    thresholds: {
        failedLoginAttempts: 3,      // Nombre de tentatives échouées avant alerte
        suspiciousActivitiesCount: 2, // Nombre d'activités suspectes avant alerte
        criticalEventsCount: 1        // Nombre d'événements critiques avant alerte
    },
    // Durée de rétention des alertes (en jours)
    retentionDays: 30
};

// Configuration de rétention des logs
const retentionConfig = {
    // Durée de conservation des logs (en jours)
    successLogsDays: 30,
    failureLogsDays: 90,
    suspiciousLogsDays: 180,
    warningLogsDays: 90,
    infoLogsDays: 30,
    criticalLogsDays: 365
};

// Abonnés aux événements de logs
let loginEventSubscribers = [];
let alertEventSubscribers = [];

// Alertes actives
let activeAlerts = [];

// IPs bloquées
let blockedIPs = [];

/**
 * Ajoute un log de connexion
 * @param {string} email - Email de l'utilisateur
 * @param {string} ipAddress - Adresse IP
 * @param {string} status - Statut du log (utiliser LOG_TYPES)
 * @param {string} details - Détails supplémentaires
 * @param {Object} metadata - Métadonnées additionnelles (optionnel)
 */
function addLoginLog(email, ipAddress, status, details, metadata = {}) {
    // Créer l'objet de log
    const log = {
        id: generateUniqueId(),
        timestamp: new Date().toISOString(),
        email: email,
        ipAddress: ipAddress,
        status: status,
        details: details,
        userAgent: metadata.userAgent || navigator.userAgent,
        geoLocation: metadata.geoLocation || null,
        metadata: metadata
    };
    
    // Ajouter le log à la liste
    securityLogs.push(log);
    
    // Sauvegarder les logs dans le stockage local
    saveLogsToStorage();
    
    // Notifier les abonnés
    notifyLoginEventSubscribers(log);
    
    // Vérifier si une alerte doit être créée
    checkForSecurityAlert(log);
    
    console.log(`[${status.toUpperCase()}] Log ajouté: ${details}`);
    
    return log;
}

/**
 * Ajoute un log général (non lié à une connexion)
 * @param {Object} logData - Données du log
 */
function addLog(logData) {
    // S'assurer que les champs requis sont présents
    if (!logData.status || !logData.details) {
        console.error('Les champs status et details sont requis pour ajouter un log');
        return null;
    }
    
    // Créer l'objet de log
    const log = {
        id: generateUniqueId(),
        timestamp: new Date().toISOString(),
        email: logData.email || 'système',
        ipAddress: logData.ipAddress || getClientIP(),
        status: logData.status,
        details: logData.details,
        userAgent: logData.userAgent || navigator.userAgent,
        geoLocation: logData.geoLocation || null,
        metadata: logData.metadata || {}
    };
    
    // Ajouter le log à la liste
    securityLogs.push(log);
    
    // Sauvegarder les logs dans le stockage local
    saveLogsToStorage();
    
    // Notifier les abonnés
    notifyLoginEventSubscribers(log);
    
    // Vérifier si une alerte doit être créée
    checkForSecurityAlert(log);
    
    console.log(`[${log.status.toUpperCase()}] Log ajouté: ${log.details}`);
    
    return log;
}

/**
 * Récupère tous les logs
 * @returns {Array} Liste de tous les logs
 */
function getAllLogs() {
    return [...securityLogs];
}

/**
 * Récupère les logs par type
 * @param {string} type - Type de log (utiliser LOG_TYPES)
 * @returns {Array} Liste des logs filtrés par type
 */
function getLogsByType(type) {
    return securityLogs.filter(log => log.status === type);
}

/**
 * Récupère les logs par utilisateur
 * @param {string} email - Email de l'utilisateur
 * @returns {Array} Liste des logs filtrés par utilisateur
 */
function getLogsByUser(email) {
    return securityLogs.filter(log => log.email === email);
}

/**
 * Récupère les logs par adresse IP
 * @param {string} ipAddress - Adresse IP
 * @returns {Array} Liste des logs filtrés par IP
 */
function getLogsByIP(ipAddress) {
    return securityLogs.filter(log => log.ipAddress === ipAddress);
}

/**
 * Vérifie si une adresse IP est suspecte
 * @param {string} ipAddress - Adresse IP à vérifier
 * @returns {Object} Résultat de l'analyse
 */
function isIPSuspicious(ipAddress) {
    // Récupérer les logs pour cette IP
    const ipLogs = getLogsByIP(ipAddress);
    
    // Calculer les statistiques
    const failedLogins = ipLogs.filter(log => log.status === LOG_TYPES.FAILURE).length;
    const suspiciousActivities = ipLogs.filter(log => log.status === LOG_TYPES.SUSPICIOUS).length;
    const criticalEvents = ipLogs.filter(log => log.status === LOG_TYPES.CRITICAL).length;
    
    // Vérifier si l'IP est bloquée
    const isBlocked = isIPBlocked(ipAddress).blocked;
    
    // Déterminer si l'IP est suspecte
    const isSuspicious = failedLogins >= securityAlertConfig.thresholds.failedLoginAttempts ||
                        suspiciousActivities >= securityAlertConfig.thresholds.suspiciousActivitiesCount ||
                        criticalEvents >= securityAlertConfig.thresholds.criticalEventsCount ||
                        isBlocked;
    
    return {
        isSuspicious,
        isBlocked,
        stats: {
            failedLogins,
            suspiciousActivities,
            criticalEvents,
            totalLogs: ipLogs.length
        }
    };
}

/**
 * Efface tous les logs
 */
function clearAllLogs() {
    securityLogs = [];
    saveLogsToStorage();
    console.log('Tous les logs ont été effacés');
}

/**
 * S'abonne aux événements de connexion
 * @param {Function} callback - Fonction à appeler lors d'un nouvel événement
 */
function subscribeToLoginEvents(callback) {
    if (typeof callback === 'function' && !loginEventSubscribers.includes(callback)) {
        loginEventSubscribers.push(callback);
        return true;
    }
    return false;
}

/**
 * Se désabonne des événements de connexion
 * @param {Function} callback - Fonction à désabonner
 */
function unsubscribeFromLoginEvents(callback) {
    const index = loginEventSubscribers.indexOf(callback);
    if (index !== -1) {
        loginEventSubscribers.splice(index, 1);
        return true;
    }
    return false;
}

/**
 * Crée une alerte de sécurité
 * @param {string} title - Titre de l'alerte
 * @param {string} description - Description de l'alerte
 * @param {string} severity - Gravité de l'alerte (utiliser LOG_TYPES)
 * @param {Object} metadata - Métadonnées additionnelles
 */
function createSecurityAlert(title, description, severity, metadata = {}) {
    const alert = {
        id: generateUniqueId(),
        timestamp: new Date().toISOString(),
        title: title,
        description: description,
        severity: severity,
        status: 'active',
        ipAddress: metadata.ipAddress || getClientIP(),
        email: metadata.email || 'système',
        metadata: metadata
    };
    
    activeAlerts.push(alert);
    
    // Sauvegarder les alertes dans le stockage local
    saveAlertsToStorage();
    
    // Notifier les abonnés
    notifyAlertEventSubscribers(alert);
    
    console.log(`[ALERTE] ${severity.toUpperCase()}: ${title}`);
    
    return alert;
}

/**
 * Récupère les alertes actives
 * @returns {Array} Liste des alertes actives
 */
function getActiveAlerts() {
    return [...activeAlerts];
}

/**
 * Résout une alerte
 * @param {string} alertId - ID de l'alerte à résoudre
 * @param {string} resolution - Description de la résolution
 */
function resolveAlert(alertId, resolution = '') {
    const alertIndex = activeAlerts.findIndex(alert => alert.id === alertId);
    
    if (alertIndex !== -1) {
        // Mettre à jour le statut de l'alerte
        activeAlerts[alertIndex].status = 'resolved';
        activeAlerts[alertIndex].resolvedAt = new Date().toISOString();
        activeAlerts[alertIndex].resolution = resolution;
        
        // Sauvegarder les alertes dans le stockage local
        saveAlertsToStorage();
        
        console.log(`Alerte ${alertId} résolue: ${resolution}`);
        return true;
    }
    
    console.warn(`Alerte ${alertId} non trouvée`);
    return false;
}

/**
 * S'abonne aux événements d'alerte
 * @param {Function} callback - Fonction à appeler lors d'une nouvelle alerte
 */
function subscribeToAlertEvents(callback) {
    if (typeof callback === 'function' && !alertEventSubscribers.includes(callback)) {
        alertEventSubscribers.push(callback);
        return true;
    }
    return false;
}

/**
 * Se désabonne des événements d'alerte
 * @param {Function} callback - Fonction à désabonner
 */
function unsubscribeFromAlertEvents(callback) {
    const index = alertEventSubscribers.indexOf(callback);
    if (index !== -1) {
        alertEventSubscribers.splice(index, 1);
        return true;
    }
    return false;
}

/**
 * Bloque une adresse IP
 * @param {string} ipAddress - Adresse IP à bloquer
 * @param {string} reason - Raison du blocage
 * @param {number} durationHours - Durée du blocage en heures (0 = permanent)
 */
function blockIP(ipAddress, reason = 'Activité suspecte', durationHours = 24) {
    // Vérifier si l'IP est déjà bloquée
    const existingBlock = blockedIPs.find(block => block.ipAddress === ipAddress);
    
    if (existingBlock) {
        // Mettre à jour le blocage existant
        existingBlock.reason = reason;
        existingBlock.blockedAt = new Date().toISOString();
        existingBlock.expiresAt = durationHours === 0 ? null : new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString();
        existingBlock.permanent = durationHours === 0;
    } else {
        // Créer un nouveau blocage
        blockedIPs.push({
            ipAddress: ipAddress,
            reason: reason,
            blockedAt: new Date().toISOString(),
            expiresAt: durationHours === 0 ? null : new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString(),
            permanent: durationHours === 0
        });
    }
    
    // Sauvegarder les IPs bloquées dans le stockage local
    saveBlockedIPsToStorage();
    
    console.log(`IP ${ipAddress} bloquée: ${reason}`);
    
    // Créer une alerte pour le blocage d'IP
    createSecurityAlert(
        `IP bloquée: ${ipAddress}`,
        `L'adresse IP ${ipAddress} a été bloquée pour la raison suivante: ${reason}`,
        LOG_TYPES.WARNING,
        { ipAddress: ipAddress }
    );
    
    return true;
}

/**
 * Vérifie si une adresse IP est bloquée
 * @param {string} ipAddress - Adresse IP à vérifier
 * @returns {Object} Résultat de la vérification
 */
function isIPBlocked(ipAddress) {
    // Nettoyer les blocages expirés
    cleanExpiredIPBlocks();
    
    // Rechercher l'IP dans la liste des blocages
    const block = blockedIPs.find(block => block.ipAddress === ipAddress);
    
    if (!block) {
        return { blocked: false };
    }
    
    return {
        blocked: true,
        reason: block.reason,
        blockedAt: block.blockedAt,
        expiresAt: block.expiresAt,
        permanent: block.permanent
    };
}

/**
 * Exporte les logs au format JSON
 * @returns {string} Logs au format JSON
 */
function exportLogsToJSON() {
    return JSON.stringify(securityLogs, null, 2);
}

/**
 * Exporte les logs au format CSV
 * @returns {string} Logs au format CSV
 */
function exportLogsToCSV() {
    // Définir les en-têtes CSV
    const headers = ['ID', 'Timestamp', 'Email', 'IP Address', 'Status', 'Details', 'User Agent', 'Geo Location'];
    
    // Convertir les logs en lignes CSV
    const rows = securityLogs.map(log => [
        log.id,
        log.timestamp,
        log.email,
        log.ipAddress,
        log.status,
        log.details,
        log.userAgent,
        log.geoLocation ? JSON.stringify(log.geoLocation) : ''
    ]);
    
    // Combiner les en-têtes et les lignes
    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    
    return csvContent;
}

/**
 * Exporte les logs pour intégration avec un SIEM
 * @returns {Object} Données formatées pour SIEM
 */
function exportLogsForSIEM() {
    return {
        source: 'Tech Shield Web Security',
        version: '1.0',
        timestamp: new Date().toISOString(),
        logs: securityLogs.map(log => ({
            event_id: log.id,
            event_time: log.timestamp,
            event_type: log.status,
            source_ip: log.ipAddress,
            user: log.email,
            message: log.details,
            user_agent: log.userAgent,
            geo_location: log.geoLocation,
            additional_data: log.metadata
        }))
    };
}

/**
 * Télécharge les logs dans le format spécifié
 * @param {string} format - Format de téléchargement ('json', 'csv', 'siem')
 */
function downloadLogs(format = 'json') {
    let content = '';
    let filename = `security-logs-${new Date().toISOString().slice(0, 10)}`;
    let contentType = '';
    
    switch (format.toLowerCase()) {
        case 'json':
            content = exportLogsToJSON();
            filename += '.json';
            contentType = 'application/json';
            break;
        case 'csv':
            content = exportLogsToCSV();
            filename += '.csv';
            contentType = 'text/csv';
            break;
        case 'siem':
            content = JSON.stringify(exportLogsForSIEM(), null, 2);
            filename += '-siem.json';
            contentType = 'application/json';
            break;
        default:
            console.error(`Format non supporté: ${format}`);
            return false;
    }
    
    // Créer un lien de téléchargement
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    
    // Ajouter à la page, cliquer et supprimer
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
    
    return true;
}

/**
 * Sauvegarde les logs dans le stockage local
 */
function saveLogsToStorage() {
    try {
        localStorage.setItem('techShield_securityLogs', JSON.stringify(securityLogs));
    } catch (error) {
        console.error('Erreur lors de la sauvegarde des logs:', error);
        
        // Si l'erreur est due à la taille du stockage, purger les anciens logs
        if (error.name === 'QuotaExceededError') {
            purgeOldLogs();
            try {
                localStorage.setItem('techShield_securityLogs', JSON.stringify(securityLogs));
            } catch (e) {
                console.error('Impossible de sauvegarder les logs même après purge:', e);
            }
        }
    }
}

/**
 * Charge les logs depuis le stockage local
 */
function loadLogsFromStorage() {
    try {
        const storedLogs = localStorage.getItem('techShield_securityLogs');
        if (storedLogs) {
            securityLogs = JSON.parse(storedLogs);
        }
    } catch (error) {
        console.error('Erreur lors du chargement des logs:', error);
    }
}

/**
 * Sauvegarde les alertes dans le stockage local
 */
function saveAlertsToStorage() {
    try {
        localStorage.setItem('techShield_securityAlerts', JSON.stringify(activeAlerts));
    } catch (error) {
        console.error('Erreur lors de la sauvegarde des alertes:', error);
    }
}

/**
 * Charge les alertes depuis le stockage local
 */
function loadAlertsFromStorage() {
    try {
        const storedAlerts = localStorage.getItem('techShield_securityAlerts');
        if (storedAlerts) {
            activeAlerts = JSON.parse(storedAlerts);
        }
    } catch (error) {
        console.error('Erreur lors du chargement des alertes:', error);
    }
}

/**
 * Sauvegarde les IPs bloquées dans le stockage local
 */
function saveBlockedIPsToStorage() {
    try {
        localStorage.setItem('techShield_blockedIPs', JSON.stringify(blockedIPs));
    } catch (error) {
        console.error('Erreur lors de la sauvegarde des IPs bloquées:', error);
    }
}

/**
 * Charge les IPs bloquées depuis le stockage local
 */
function loadBlockedIPsFromStorage() {
    try {
        const storedBlockedIPs = localStorage.getItem('techShield_blockedIPs');
        if (storedBlockedIPs) {
            blockedIPs = JSON.parse(storedBlockedIPs);
        }
    } catch (error) {
        console.error('Erreur lors du chargement des IPs bloquées:', error);
    }
}

/**
 * Purge les logs anciens selon la configuration de rétention
 */
function purgeOldLogs() {
    const now = new Date();
    
    // Filtrer les logs selon leur type et date de rétention
    securityLogs = securityLogs.filter(log => {
        const logDate = new Date(log.timestamp);
        const ageInDays = (now - logDate) / (1000 * 60 * 60 * 24);
        
        switch (log.status) {
            case LOG_TYPES.SUCCESS:
                return ageInDays <= retentionConfig.successLogsDays;
            case LOG_TYPES.FAILURE:
                return ageInDays <= retentionConfig.failureLogsDays;
            case LOG_TYPES.SUSPICIOUS:
                return ageInDays <= retentionConfig.suspiciousLogsDays;
            case LOG_TYPES.WARNING:
                return ageInDays <= retentionConfig.warningLogsDays;
            case LOG_TYPES.INFO:
                return ageInDays <= retentionConfig.infoLogsDays;
            case LOG_TYPES.CRITICAL:
                return ageInDays <= retentionConfig.criticalLogsDays;
            default:
                return ageInDays <= 30; // Valeur par défaut
        }
    });
    
    console.log(`Purge des logs anciens effectuée. ${securityLogs.length} logs conservés.`);
}

/**
 * Nettoie les blocages d'IP expirés
 */
function cleanExpiredIPBlocks() {
    const now = new Date();
    
    // Filtrer les blocages non expirés
    blockedIPs = blockedIPs.filter(block => {
        // Les blocages permanents ne sont jamais expirés
        if (block.permanent) return true;
        
        // Vérifier si le blocage est expiré
        return block.expiresAt && new Date(block.expiresAt) > now;
    });
    
    // Sauvegarder les IPs bloquées mises à jour
    saveBlockedIPsToStorage();
}

/**
 * Vérifie si une alerte de sécurité doit être créée pour un log
 * @param {Object} log - Log à vérifier
 */
function checkForSecurityAlert(log) {
    // Vérifier les tentatives de connexion échouées
    if (log.status === LOG_TYPES.FAILURE) {
        const recentFailedLogins = securityLogs.filter(l => 
            l.status === LOG_TYPES.FAILURE && 
            l.email === log.email &&
            l.ipAddress === log.ipAddress &&
            new Date(l.timestamp) >= new Date(Date.now() - securityAlertConfig.thresholds.timeWindowMinutes * 60 * 1000)
        );
        
        if (recentFailedLogins.length >= securityAlertConfig.thresholds.failedLoginAttempts) {
            createSecurityAlert(
                `Tentatives de connexion multiples échouées`,
                `${recentFailedLogins.length} tentatives de connexion échouées pour ${log.email} depuis l'IP ${log.ipAddress}`,
                LOG_TYPES.WARNING,
                { email: log.email, ipAddress: log.ipAddress }
            );
        }
    }
    
    // Vérifier les activités suspectes
    if (log.status === LOG_TYPES.SUSPICIOUS) {
        const recentSuspiciousActivities = securityLogs.filter(l => 
            l.status === LOG_TYPES.SUSPICIOUS && 
            l.email === log.email &&
            new Date(l.timestamp) >= new Date(Date.now() - securityAlertConfig.thresholds.timeWindowMinutes * 60 * 1000)
        );
        
        if (recentSuspiciousActivities.length >= securityAlertConfig.thresholds.suspiciousActivitiesCount) {
            createSecurityAlert(
                `Activités suspectes détectées`,
                `${recentSuspiciousActivities.length} activités suspectes pour ${log.email}`,
                LOG_TYPES.WARNING,
                { email: log.email }
            );
        }
    }
    
    // Créer une alerte immédiate pour les événements critiques
    if (log.status === LOG_TYPES.CRITICAL) {
        createSecurityAlert(
            `Événement critique détecté`,
            log.details,
            LOG_TYPES.CRITICAL,
            { email: log.email, ipAddress: log.ipAddress }
        );
    }
}

/**
 * Notifie les abonnés aux événements de connexion
 * @param {Object} log - Log à notifier
 */
function notifyLoginEventSubscribers(log) {
    loginEventSubscribers.forEach(callback => {
        try {
            callback(log);
        } catch (error) {
            console.error('Erreur lors de la notification d\'un abonné aux événements de connexion:', error);
        }
    });
}

/**
 * Notifie les abonnés aux événements d'alerte
 * @param {Object} alert - Alerte à notifier
 */
function notifyAlertEventSubscribers(alert) {
    alertEventSubscribers.forEach(callback => {
        try {
            callback(alert);
        } catch (error) {
            console.error('Erreur lors de la notification d\'un abonné aux événements d\'alerte:', error);
        }
    });
}

/**
 * Génère un identifiant unique
 * @returns {string} Identifiant unique
 */
function generateUniqueId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

/**
 * Récupère l'adresse IP du client
 * @returns {string} Adresse IP du client
 */
function getClientIP() {
    // Dans un environnement réel, cette fonction serait implémentée côté serveur
    // Pour le moment, on retourne une valeur factice
    return '127.0.0.1';
}

/**
 * Initialise le module de logs de sécurité
 */
function init() {
    // Charger les données depuis le stockage local
    loadLogsFromStorage();
    loadAlertsFromStorage();
    loadBlockedIPsFromStorage();
    
    // Nettoyer les données expirées
    purgeOldLogs();
    cleanExpiredIPBlocks();
    
    console.log('Module de logs de sécurité initialisé');
}

// Exposer les fonctions publiques
window.securityLogs = {
    LOG_TYPES,
    addLoginLog,
    addLog,
    getAllLogs,
    getLogsByType,
    getLogsByUser,
    getLogsByIP,
    isIPSuspicious,
    clearAllLogs,
    subscribeToLoginEvents,
    unsubscribeFromLoginEvents,
    createSecurityAlert,
    getActiveAlerts,
    resolveAlert,
    subscribeToAlertEvents,
    unsubscribeFromAlertEvents,
    blockIP,
    isIPBlocked,
    exportLogsToJSON,
    exportLogsToCSV,
    exportLogsForSIEM,
    downloadLogs,
    saveLogsToStorage,
    loadLogsFromStorage,
    purgeOldLogs,
    init
};

// Initialiser le module
init();