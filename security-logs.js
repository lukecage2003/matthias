// Système de journalisation de sécurité pour Tech Shield

// Structure pour stocker les journaux de connexion
const securityLogs = [];

// Types de journaux
const LOG_TYPES = {
    SUCCESS: 'success',
    FAILURE: 'failure',
    SUSPICIOUS: 'suspicious',
    INFO: 'info',
    WARNING: 'warning',
    CRITICAL: 'critical'
};

// Configuration des alertes de sécurité
const securityAlertConfig = {
    failedLoginThreshold: 5,  // Nombre de tentatives échouées avant alerte
    timeWindowMinutes: 15,    // Fenêtre de temps pour les tentatives (minutes)
    alertDurationMinutes: 30  // Durée pendant laquelle l'alerte reste active
};

// Stockage des alertes actives
const activeAlerts = [];

// Stockage des IPs bloquées temporairement
const blockedIPs = {};

// Système d'événements pour les connexions en temps réel
const loginEventListeners = [];

// Fonction pour s'abonner aux événements de connexion
function subscribeToLoginEvents(callback) {
    loginEventListeners.push(callback);
    return loginEventListeners.length - 1; // Retourne l'index pour pouvoir se désabonner plus tard
}

// Fonction pour se désabonner des événements de connexion
function unsubscribeFromLoginEvents(index) {
    if (index >= 0 && index < loginEventListeners.length) {
        loginEventListeners[index] = null;
    }
}

// Fonction pour ajouter un journal de connexion
function addLoginLog(email, ipAddress, status, details) {
    const log = {
        timestamp: new Date().toISOString(),
        email: email,
        ipAddress: ipAddress,
        status: status,
        details: details
    };
    
    securityLogs.push(log);
    
    // Dans un environnement de production, on enverrait ces logs à un serveur
    console.log('Security Log:', log);
    
    // Stocker les logs dans le localStorage pour la démonstration
    saveLogsToStorage();
    
    // Notifier tous les abonnés aux événements de connexion
    loginEventListeners.forEach(listener => {
        if (listener) {
            listener(log);
        }
    });
    
    return log;
}

// Fonction pour obtenir tous les journaux
function getAllLogs() {
    // Charger les logs depuis le localStorage
    loadLogsFromStorage();
    return securityLogs;
}

// Fonction pour obtenir les journaux filtrés par type
function getLogsByType(type) {
    return securityLogs.filter(log => log.status === type);
}

// Fonction pour obtenir les journaux d'un utilisateur spécifique
function getLogsByUser(email) {
    return securityLogs.filter(log => log.email === email);
}

// Fonction pour obtenir les journaux d'une adresse IP spécifique
function getLogsByIP(ipAddress) {
    return securityLogs.filter(log => log.ipAddress === ipAddress);
}

// Fonction pour vérifier si une adresse IP est suspecte
function isIPSuspicious(ipAddress) {
    const ipLogs = getLogsByIP(ipAddress);
    const failedAttempts = ipLogs.filter(log => log.status === LOG_TYPES.FAILURE);
    
    // Si plus de X tentatives échouées dans les dernières Y minutes, considérer comme suspect
    if (failedAttempts.length >= securityAlertConfig.failedLoginThreshold) {
        const timeWindowAgo = new Date(Date.now() - securityAlertConfig.timeWindowMinutes * 60 * 1000).toISOString();
        const recentFailedAttempts = failedAttempts.filter(log => log.timestamp >= timeWindowAgo);
        
        if (recentFailedAttempts.length >= securityAlertConfig.failedLoginThreshold) {
            // Créer une alerte si elle n'existe pas déjà
            createSecurityAlert(ipAddress, 'Tentatives de connexion multiples échouées', LOG_TYPES.SUSPICIOUS);
            return true;
        }
    }
    
    return false;
}

// Fonction pour créer une alerte de sécurité
function createSecurityAlert(ipAddress, reason, severity) {
    // Vérifier si une alerte similaire existe déjà
    const existingAlertIndex = activeAlerts.findIndex(alert => 
        alert.ipAddress === ipAddress && alert.reason === reason);
    
    if (existingAlertIndex !== -1) {
        // Mettre à jour l'alerte existante
        activeAlerts[existingAlertIndex].timestamp = new Date().toISOString();
        activeAlerts[existingAlertIndex].count += 1;
        return activeAlerts[existingAlertIndex];
    }
    
    // Créer une nouvelle alerte
    const alert = {
        id: generateAlertId(),
        timestamp: new Date().toISOString(),
        ipAddress: ipAddress,
        reason: reason,
        severity: severity,
        count: 1,
        status: 'active'
    };
    
    activeAlerts.push(alert);
    
    // Enregistrer l'alerte dans les logs
    addLoginLog('système', ipAddress, severity, `ALERTE: ${reason}`);
    
    // Notifier les abonnés aux événements
    notifyAlertSubscribers(alert);
    
    return alert;
}

// Fonction pour générer un ID unique pour les alertes
function generateAlertId() {
    return 'alert-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
}

// Système d'événements pour les alertes
const alertEventListeners = [];

// Fonction pour s'abonner aux événements d'alerte
function subscribeToAlertEvents(callback) {
    alertEventListeners.push(callback);
    return alertEventListeners.length - 1;
}

// Fonction pour se désabonner des événements d'alerte
function unsubscribeFromAlertEvents(index) {
    if (index >= 0 && index < alertEventListeners.length) {
        alertEventListeners[index] = null;
    }
}

// Fonction pour notifier les abonnés aux alertes
function notifyAlertSubscribers(alert) {
    alertEventListeners.forEach(listener => {
        if (listener) {
            listener(alert);
        }
    });
}

// Fonction pour obtenir toutes les alertes actives
function getActiveAlerts() {
    // Nettoyer les alertes expirées
    cleanExpiredAlerts();
    return activeAlerts;
}

// Fonction pour nettoyer les alertes expirées
function cleanExpiredAlerts() {
    const now = new Date();
    const expirationTime = new Date(now.getTime() - (securityAlertConfig.alertDurationMinutes * 60 * 1000));
    
    // Filtrer les alertes expirées
    const expiredAlerts = activeAlerts.filter(alert => 
        new Date(alert.timestamp) < expirationTime);
    
    // Marquer les alertes expirées comme résolues
    expiredAlerts.forEach(alert => {
        alert.status = 'resolved';
        // Ajouter un log pour indiquer que l'alerte est résolue
        addLoginLog('système', alert.ipAddress, LOG_TYPES.INFO, 
            `Alerte automatiquement résolue: ${alert.reason}`);
    });
    
    // Supprimer les alertes expirées du tableau des alertes actives
    for (let i = activeAlerts.length - 1; i >= 0; i--) {
        if (activeAlerts[i].status === 'resolved') {
            activeAlerts.splice(i, 1);
        }
    }
}

// Fonction pour résoudre manuellement une alerte
function resolveAlert(alertId) {
    const alertIndex = activeAlerts.findIndex(alert => alert.id === alertId);
    
    if (alertIndex !== -1) {
        const alert = activeAlerts[alertIndex];
        alert.status = 'resolved';
        
        // Ajouter un log pour indiquer que l'alerte est résolue manuellement
        addLoginLog('système', alert.ipAddress, LOG_TYPES.INFO, 
            `Alerte manuellement résolue: ${alert.reason}`);
        
        // Supprimer l'alerte du tableau des alertes actives
        activeAlerts.splice(alertIndex, 1);
        
        return true;
    }
    
    return false;
}

// Fonction pour bloquer temporairement une adresse IP
function blockIP(ipAddress, durationMinutes = 30) {
    const expirationTime = new Date();
    expirationTime.setMinutes(expirationTime.getMinutes() + durationMinutes);
    
    blockedIPs[ipAddress] = expirationTime.toISOString();
    
    // Ajouter un log pour indiquer que l'IP est bloquée
    addLoginLog('système', ipAddress, LOG_TYPES.WARNING, 
        `IP bloquée temporairement pour ${durationMinutes} minutes`);
    
    return true;
}

// Fonction pour vérifier si une IP est bloquée
function isIPBlocked(ipAddress) {
    if (blockedIPs[ipAddress]) {
        const now = new Date();
        const blockExpiration = new Date(blockedIPs[ipAddress]);
        
        if (now < blockExpiration) {
            return { 
                blocked: true, 
                expiresAt: blockedIPs[ipAddress] 
            };
        } else {
            // Supprimer l'IP de la liste des IPs bloquées si le blocage a expiré
            delete blockedIPs[ipAddress];
        }
    }
    
    return { blocked: false };
}

// Fonction pour sauvegarder les logs dans le localStorage
function saveLogsToStorage() {
    localStorage.setItem('securityLogs', JSON.stringify(securityLogs));
}

// Fonction pour charger les logs depuis le localStorage
function loadLogsFromStorage() {
    const storedLogs = localStorage.getItem('securityLogs');
    if (storedLogs) {
        // Fusionner les logs stockés avec les logs actuels
        const parsedLogs = JSON.parse(storedLogs);
        
        // Vider le tableau actuel et ajouter les logs stockés
        securityLogs.length = 0;
        parsedLogs.forEach(log => securityLogs.push(log));
    }
}

// Fonction pour effacer tous les logs
function clearAllLogs() {
    securityLogs.length = 0;
    localStorage.removeItem('securityLogs');
}

// Fonction pour exporter les logs au format JSON
function exportLogsToJSON() {
    return JSON.stringify(securityLogs, null, 2);
}

// Fonction pour exporter les logs au format CSV
function exportLogsToCSV() {
    if (securityLogs.length === 0) {
        return '';
    }
    
    // Définir les en-têtes CSV
    const headers = ['Date', 'Utilisateur', 'Adresse IP', 'Statut', 'Détails'];
    
    // Créer les lignes de données
    const rows = securityLogs.map(log => {
        const date = new Date(log.timestamp);
        const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
        return [
            formattedDate,
            log.email || 'N/A',
            log.ipAddress,
            log.status,
            log.details
        ];
    });
    
    // Combiner les en-têtes et les lignes
    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.join(','))
    ].join('\n');
    
    return csvContent;
}

// Fonction pour exporter les logs au format compatible avec ELK/Splunk
function exportLogsForSIEM() {
    return securityLogs.map(log => {
        // Formater les logs pour être compatibles avec ELK/Splunk
        return {
            '@timestamp': log.timestamp,
            'event': {
                'type': 'security',
                'category': 'authentication',
                'action': log.status
            },
            'user': {
                'name': log.email || 'unknown'
            },
            'source': {
                'ip': log.ipAddress
            },
            'message': log.details,
            'log': {
                'level': log.status === LOG_TYPES.SUCCESS ? 'info' :
                        log.status === LOG_TYPES.FAILURE ? 'error' :
                        log.status === LOG_TYPES.SUSPICIOUS ? 'warning' :
                        log.status === LOG_TYPES.WARNING ? 'warning' :
                        log.status === LOG_TYPES.CRITICAL ? 'critical' : 'info'
            }
        };
    });
}

// Fonction pour télécharger les logs exportés
function downloadLogs(format = 'json') {
    let content = '';
    let mimeType = '';
    let extension = '';
    
    switch(format.toLowerCase()) {
        case 'json':
            content = exportLogsToJSON();
            mimeType = 'application/json';
            extension = 'json';
            break;
        case 'csv':
            content = exportLogsToCSV();
            mimeType = 'text/csv';
            extension = 'csv';
            break;
        case 'siem':
            content = JSON.stringify(exportLogsForSIEM(), null, 2);
            mimeType = 'application/json';
            extension = 'siem.json';
            break;
        default:
            throw new Error('Format non supporté');
    }
    
    // Créer un objet Blob avec le contenu
    const blob = new Blob([content], { type: mimeType });
    
    // Créer un URL pour le blob
    const url = URL.createObjectURL(blob);
    
    // Créer un élément a pour le téléchargement
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-logs-${new Date().toISOString().slice(0, 10)}.${extension}`;
    
    // Ajouter l'élément au DOM, cliquer dessus, puis le supprimer
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    // Libérer l'URL
    URL.revokeObjectURL(url);
    
    return true;
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.securityLogs = {
    LOG_TYPES,
    addLoginLog,
    getAllLogs,
    getLogsByType,
    getLogsByUser,
    getLogsByIP,
    isIPSuspicious,
    clearAllLogs,
    subscribeToLoginEvents,
    unsubscribeFromLoginEvents,
    // Nouvelles fonctions d'alerte
    createSecurityAlert,
    getActiveAlerts,
    resolveAlert,
    subscribeToAlertEvents,
    unsubscribeFromAlertEvents,
    blockIP,
    isIPBlocked,
    // Fonctions d'exportation
    exportLogsToJSON,
    exportLogsToCSV,
    exportLogsForSIEM,
    downloadLogs
};