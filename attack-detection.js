// Module de détection d'attaques pour Tech Shield
// Analyse avancée des logs pour identifier les tentatives d'attaques

/**
 * Configuration du système de détection d'attaques
 */
const attackDetectionConfig = {
    // Activer la détection automatique
    enabled: true,
    
    // Intervalle d'analyse des logs (en millisecondes)
    analysisInterval: 60000, // 1 minute
    
    // Seuils de détection
    thresholds: {
        // Nombre de tentatives de connexion échouées avant alerte
        failedLoginAttempts: 5,
        
        // Période de surveillance pour les tentatives de connexion (en minutes)
        loginAttemptWindow: 10,
        
        // Nombre de requêtes suspectes avant alerte
        suspiciousRequests: 3,
        
        // Période de surveillance pour les requêtes suspectes (en minutes)
        suspiciousRequestWindow: 5,
        
        // Nombre d'accès refusés avant alerte
        accessDenied: 3,
        
        // Période de surveillance pour les accès refusés (en minutes)
        accessDeniedWindow: 15,
        
        // Nombre d'injections SQL détectées avant alerte
        sqlInjectionAttempts: 1,
        
        // Nombre de tentatives XSS détectées avant alerte
        xssAttempts: 1
    },
    
    // Patterns de détection d'attaques
    patterns: {
        // Patterns d'injection SQL
        sqlInjection: [
            "'\\s*OR\\s*'\\s*'\\s*=\\s*'", // ' OR ' = '
            "'\\s*OR\\s*[0-9]\\s*=\\s*[0-9]", // ' OR 1 = 1
            "--\\s", // Commentaire SQL
            ";\\s*DROP\\s+TABLE", // ; DROP TABLE
            "UNION\\s+SELECT", // UNION SELECT
            "INSERT\\s+INTO", // INSERT INTO
            "DELETE\\s+FROM", // DELETE FROM
            "EXEC\\s*\\(\\s*xp_", // EXEC(xp_
            "SELECT\\s+\\*\\s+FROM" // SELECT * FROM
        ],
        
        // Patterns d'attaque XSS
        xss: [
            "<script[^>]*>.*?</script>", // <script>...</script>
            "javascript:\\s*\\(", // javascript:(
            "onload\\s*=", // onload=
            "onerror\\s*=", // onerror=
            "onclick\\s*=", // onclick=
            "alert\\s*\\(", // alert(
            "document\\.cookie", // document.cookie
            "<img[^>]+src[^>]+onerror[^>]+>", // <img src=x onerror=...>
            "eval\\s*\\(" // eval(
        ],
        
        // Patterns d'attaque par chemin de fichier
        pathTraversal: [
            "\\.\\./", // ../
            "\\.\\.\\\\" // ..\
        ],
        
        // Patterns d'attaque par commande
        commandInjection: [
            "\\|\\s*[a-zA-Z]+", // | command
            ";\\s*[a-zA-Z]+", // ; command
            "&&\\s*[a-zA-Z]+", // && command
            "\\$\\([^)]*\\)" // $(command)
        ]
    },
    
    // Actions automatiques
    actions: {
        // Bloquer automatiquement les IPs suspectes
        autoBlockIPs: true,
        
        // Durée du blocage automatique (en minutes)
        autoBlockDuration: 30,
        
        // Envoyer des notifications
        sendNotifications: true,
        
        // Enregistrer les attaques dans un fichier séparé
        logToFile: true
    }
};

// Stockage des alertes d'attaques
let attackAlerts = [];

// Stockage des IPs bloquées automatiquement
let autoBlockedIPs = {};

// Référence à l'intervalle d'analyse
let analysisIntervalId = null;

/**
 * Initialise le système de détection d'attaques
 * @param {Object} config - Configuration optionnelle
 * @returns {boolean} - Succès de l'initialisation
 */
function initAttackDetection(config = {}) {
    try {
        // Fusionner la configuration fournie avec la configuration par défaut
        Object.assign(attackDetectionConfig, config);
        
        console.log('Système de détection d\'attaques initialisé');
        
        // Démarrer l'analyse périodique si activée
        if (attackDetectionConfig.enabled) {
            startPeriodicAnalysis();
        }
        
        // Journaliser l'initialisation si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: 'Système de détection d\'attaques initialisé',
                source: 'attack-detection'
            });
        }
        
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'initialisation du système de détection d\'attaques:', error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: 'Échec de l\'initialisation du système de détection d\'attaques: ' + error.message,
                source: 'attack-detection'
            });
        }
        
        return false;
    }
}

/**
 * Démarre l'analyse périodique des logs
 */
function startPeriodicAnalysis() {
    // Arrêter l'analyse précédente si elle existe
    if (analysisIntervalId) {
        clearInterval(analysisIntervalId);
    }
    
    // Démarrer une nouvelle analyse périodique
    analysisIntervalId = setInterval(() => {
        analyzeSecurityLogs();
    }, attackDetectionConfig.analysisInterval);
    
    console.log(`Analyse périodique démarrée (intervalle: ${attackDetectionConfig.analysisInterval / 1000}s)`);
}

/**
 * Arrête l'analyse périodique des logs
 */
function stopPeriodicAnalysis() {
    if (analysisIntervalId) {
        clearInterval(analysisIntervalId);
        analysisIntervalId = null;
        console.log('Analyse périodique arrêtée');
    }
}

/**
 * Analyse les logs de sécurité pour détecter des attaques potentielles
 * @returns {Array} - Liste des alertes générées
 */
function analyzeSecurityLogs() {
    try {
        // Vérifier si le module de logs est disponible
        if (!window.securityLogs || !window.securityLogs.getAllLogs) {
            console.warn('Module de logs non disponible pour l\'analyse');
            return [];
        }
        
        // Récupérer tous les logs
        const logs = window.securityLogs.getAllLogs();
        
        // Générer des alertes basées sur l'analyse
        const newAlerts = [];
        
        // Détecter les tentatives de connexion échouées
        const loginAlerts = detectFailedLoginAttempts(logs);
        newAlerts.push(...loginAlerts);
        
        // Détecter les requêtes suspectes
        const requestAlerts = detectSuspiciousRequests(logs);
        newAlerts.push(...requestAlerts);
        
        // Détecter les accès refusés
        const accessAlerts = detectAccessDenied(logs);
        newAlerts.push(...accessAlerts);
        
        // Détecter les tentatives d'injection SQL
        const sqlAlerts = detectSQLInjection(logs);
        newAlerts.push(...sqlAlerts);
        
        // Détecter les tentatives XSS
        const xssAlerts = detectXSSAttempts(logs);
        newAlerts.push(...xssAlerts);
        
        // Traiter les nouvelles alertes
        processNewAlerts(newAlerts);
        
        return newAlerts;
    } catch (error) {
        console.error('Erreur lors de l\'analyse des logs:', error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: 'Erreur lors de l\'analyse des logs: ' + error.message,
                source: 'attack-detection'
            });
        }
        
        return [];
    }
}

/**
 * Détecte les tentatives de connexion échouées
 * @param {Array} logs - Liste des logs de sécurité
 * @returns {Array} - Liste des alertes générées
 */
function detectFailedLoginAttempts(logs) {
    const alerts = [];
    const ipAttempts = {};
    const userAttempts = {};
    
    // Définir la fenêtre de temps pour l'analyse
    const cutoffTime = new Date();
    cutoffTime.setMinutes(cutoffTime.getMinutes() - attackDetectionConfig.thresholds.loginAttemptWindow);
    
    // Filtrer les logs pertinents (échecs de connexion récents)
    const failedLogins = logs.filter(log => 
        log.status === 'failure' && 
        new Date(log.timestamp) >= cutoffTime &&
        log.details && log.details.includes('connexion') &&
        log.ipAddress
    );
    
    // Compter les tentatives par IP
    failedLogins.forEach(log => {
        const ip = log.ipAddress;
        ipAttempts[ip] = (ipAttempts[ip] || 0) + 1;
        
        // Compter aussi par utilisateur si disponible
        if (log.email) {
            userAttempts[log.email] = (userAttempts[log.email] || 0) + 1;
        }
    });
    
    // Vérifier les seuils par IP
    for (const [ip, count] of Object.entries(ipAttempts)) {
        if (count >= attackDetectionConfig.thresholds.failedLoginAttempts) {
            // Créer une alerte
            alerts.push({
                type: 'brute_force',
                severity: 'high',
                source: ip,
                details: `Tentative de force brute détectée: ${count} échecs de connexion depuis l'IP ${ip}`,
                timestamp: new Date().toISOString(),
                metadata: {
                    ip,
                    attemptCount: count,
                    timeWindow: `${attackDetectionConfig.thresholds.loginAttemptWindow} minutes`
                }
            });
        }
    }
    
    // Vérifier les seuils par utilisateur
    for (const [email, count] of Object.entries(userAttempts)) {
        if (count >= attackDetectionConfig.thresholds.failedLoginAttempts) {
            // Créer une alerte
            alerts.push({
                type: 'account_attack',
                severity: 'medium',
                source: email,
                details: `Attaque sur compte détectée: ${count} échecs de connexion pour l'utilisateur ${email}`,
                timestamp: new Date().toISOString(),
                metadata: {
                    email,
                    attemptCount: count,
                    timeWindow: `${attackDetectionConfig.thresholds.loginAttemptWindow} minutes`
                }
            });
        }
    }
    
    return alerts;
}

/**
 * Détecte les requêtes suspectes
 * @param {Array} logs - Liste des logs de sécurité
 * @returns {Array} - Liste des alertes générées
 */
function detectSuspiciousRequests(logs) {
    const alerts = [];
    const ipRequests = {};
    
    // Définir la fenêtre de temps pour l'analyse
    const cutoffTime = new Date();
    cutoffTime.setMinutes(cutoffTime.getMinutes() - attackDetectionConfig.thresholds.suspiciousRequestWindow);
    
    // Filtrer les logs pertinents (requêtes suspectes récentes)
    const suspiciousLogs = logs.filter(log => 
        log.status === 'suspicious' && 
        new Date(log.timestamp) >= cutoffTime &&
        log.ipAddress
    );
    
    // Compter les requêtes suspectes par IP
    suspiciousLogs.forEach(log => {
        const ip = log.ipAddress;
        ipRequests[ip] = (ipRequests[ip] || 0) + 1;
    });
    
    // Vérifier les seuils par IP
    for (const [ip, count] of Object.entries(ipRequests)) {
        if (count >= attackDetectionConfig.thresholds.suspiciousRequests) {
            // Créer une alerte
            alerts.push({
                type: 'suspicious_activity',
                severity: 'medium',
                source: ip,
                details: `Activité suspecte détectée: ${count} requêtes suspectes depuis l'IP ${ip}`,
                timestamp: new Date().toISOString(),
                metadata: {
                    ip,
                    requestCount: count,
                    timeWindow: `${attackDetectionConfig.thresholds.suspiciousRequestWindow} minutes`
                }
            });
        }
    }
    
    return alerts;
}

/**
 * Détecte les accès refusés
 * @param {Array} logs - Liste des logs de sécurité
 * @returns {Array} - Liste des alertes générées
 */
function detectAccessDenied(logs) {
    const alerts = [];
    const ipAccess = {};
    
    // Définir la fenêtre de temps pour l'analyse
    const cutoffTime = new Date();
    cutoffTime.setMinutes(cutoffTime.getMinutes() - attackDetectionConfig.thresholds.accessDeniedWindow);
    
    // Filtrer les logs pertinents (accès refusés récents)
    const accessDeniedLogs = logs.filter(log => 
        (log.details && log.details.includes('refusé')) && 
        new Date(log.timestamp) >= cutoffTime &&
        log.ipAddress
    );
    
    // Compter les accès refusés par IP
    accessDeniedLogs.forEach(log => {
        const ip = log.ipAddress;
        ipAccess[ip] = (ipAccess[ip] || 0) + 1;
    });
    
    // Vérifier les seuils par IP
    for (const [ip, count] of Object.entries(ipAccess)) {
        if (count >= attackDetectionConfig.thresholds.accessDenied) {
            // Créer une alerte
            alerts.push({
                type: 'unauthorized_access',
                severity: 'medium',
                source: ip,
                details: `Tentatives d'accès non autorisé: ${count} accès refusés depuis l'IP ${ip}`,
                timestamp: new Date().toISOString(),
                metadata: {
                    ip,
                    accessCount: count,
                    timeWindow: `${attackDetectionConfig.thresholds.accessDeniedWindow} minutes`
                }
            });
        }
    }
    
    return alerts;
}

/**
 * Détecte les tentatives d'injection SQL
 * @param {Array} logs - Liste des logs de sécurité
 * @returns {Array} - Liste des alertes générées
 */
function detectSQLInjection(logs) {
    const alerts = [];
    
    // Créer une expression régulière combinée pour tous les patterns d'injection SQL
    const sqlPatterns = attackDetectionConfig.patterns.sqlInjection;
    const sqlRegex = new RegExp(sqlPatterns.join('|'), 'i');
    
    // Parcourir tous les logs pour détecter les patterns d'injection SQL
    logs.forEach(log => {
        // Vérifier dans les détails et les métadonnées
        let detectedPattern = null;
        
        // Vérifier dans les détails
        if (log.details && sqlRegex.test(log.details)) {
            detectedPattern = log.details.match(sqlRegex)[0];
        }
        
        // Vérifier dans les métadonnées si disponibles
        if (!detectedPattern && log.metadata) {
            const metadataStr = JSON.stringify(log.metadata);
            if (sqlRegex.test(metadataStr)) {
                detectedPattern = metadataStr.match(sqlRegex)[0];
            }
        }
        
        // Si un pattern est détecté, créer une alerte
        if (detectedPattern) {
            alerts.push({
                type: 'sql_injection',
                severity: 'critical',
                source: log.ipAddress || 'unknown',
                details: `Tentative d'injection SQL détectée: ${detectedPattern}`,
                timestamp: new Date().toISOString(),
                metadata: {
                    pattern: detectedPattern,
                    logId: log.id,
                    originalTimestamp: log.timestamp
                }
            });
        }
    });
    
    return alerts;
}

/**
 * Détecte les tentatives d'attaque XSS
 * @param {Array} logs - Liste des logs de sécurité
 * @returns {Array} - Liste des alertes générées
 */
function detectXSSAttempts(logs) {
    const alerts = [];
    
    // Créer une expression régulière combinée pour tous les patterns XSS
    const xssPatterns = attackDetectionConfig.patterns.xss;
    const xssRegex = new RegExp(xssPatterns.join('|'), 'i');
    
    // Parcourir tous les logs pour détecter les patterns XSS
    logs.forEach(log => {
        // Vérifier dans les détails et les métadonnées
        let detectedPattern = null;
        
        // Vérifier dans les détails
        if (log.details && xssRegex.test(log.details)) {
            detectedPattern = log.details.match(xssRegex)[0];
        }
        
        // Vérifier dans les métadonnées si disponibles
        if (!detectedPattern && log.metadata) {
            const metadataStr = JSON.stringify(log.metadata);
            if (xssRegex.test(metadataStr)) {
                detectedPattern = metadataStr.match(xssRegex)[0];
            }
        }
        
        // Si un pattern est détecté, créer une alerte
        if (detectedPattern) {
            alerts.push({
                type: 'xss_attempt',
                severity: 'critical',
                source: log.ipAddress || 'unknown',
                details: `Tentative d'attaque XSS détectée: ${detectedPattern}`,
                timestamp: new Date().toISOString(),
                metadata: {
                    pattern: detectedPattern,
                    logId: log.id,
                    originalTimestamp: log.timestamp
                }
            });
        }
    });
    
    return alerts;
}

/**
 * Traite les nouvelles alertes générées
 * @param {Array} newAlerts - Liste des nouvelles alertes
 */
function processNewAlerts(newAlerts) {
    if (newAlerts.length === 0) {
        return;
    }
    
    console.log(`${newAlerts.length} nouvelle(s) alerte(s) de sécurité détectée(s)`);
    
    // Ajouter les alertes à la liste globale
    attackAlerts.push(...newAlerts);
    
    // Limiter la taille de la liste d'alertes (garder les 100 plus récentes)
    if (attackAlerts.length > 100) {
        attackAlerts = attackAlerts.slice(-100);
    }
    
    // Traiter chaque alerte
    newAlerts.forEach(alert => {
        // Journaliser l'alerte si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: mapSeverityToLogType(alert.severity),
                details: alert.details,
                source: 'attack-detection',
                ipAddress: alert.source,
                metadata: alert.metadata
            });
        }
        
        // Bloquer automatiquement l'IP si configuré et si c'est une IP valide
        if (attackDetectionConfig.actions.autoBlockIPs && 
            alert.source && 
            isValidIP(alert.source) &&
            (alert.severity === 'critical' || alert.severity === 'high')) {
            
            blockIP(alert.source, alert.type);
        }
        
        // Envoyer une notification si configuré
        if (attackDetectionConfig.actions.sendNotifications) {
            sendAlertNotification(alert);
        }
    });
}

/**
 * Mappe la sévérité d'une alerte à un type de log
 * @param {string} severity - Sévérité de l'alerte
 * @returns {string} - Type de log correspondant
 */
function mapSeverityToLogType(severity) {
    if (!window.securityLogs || !window.securityLogs.LOG_TYPES) {
        return severity;
    }
    
    switch (severity) {
        case 'critical':
            return window.securityLogs.LOG_TYPES.CRITICAL;
        case 'high':
            return window.securityLogs.LOG_TYPES.WARNING;
        case 'medium':
            return window.securityLogs.LOG_TYPES.SUSPICIOUS;
        case 'low':
            return window.securityLogs.LOG_TYPES.INFO;
        default:
            return window.securityLogs.LOG_TYPES.INFO;
    }
}

/**
 * Vérifie si une chaîne est une adresse IP valide
 * @param {string} ip - Adresse IP à vérifier
 * @returns {boolean} - True si l'IP est valide
 */
function isValidIP(ip) {
    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

/**
 * Bloque une adresse IP
 * @param {string} ip - Adresse IP à bloquer
 * @param {string} reason - Raison du blocage
 * @returns {boolean} - Succès du blocage
 */
function blockIP(ip, reason) {
    try {
        // Vérifier si l'IP est déjà bloquée
        if (autoBlockedIPs[ip]) {
            console.log(`L'IP ${ip} est déjà bloquée`);
            return true;
        }
        
        // Ajouter l'IP à la liste des IPs bloquées automatiquement
        const expirationTime = new Date();
        expirationTime.setMinutes(expirationTime.getMinutes() + attackDetectionConfig.actions.autoBlockDuration);
        
        autoBlockedIPs[ip] = {
            reason: reason,
            timestamp: new Date().toISOString(),
            expiresAt: expirationTime.toISOString()
        };
        
        console.log(`IP ${ip} bloquée automatiquement pour ${attackDetectionConfig.actions.autoBlockDuration} minutes`);
        
        // Utiliser le module de liste blanche si disponible
        if (window.ipWhitelist && window.ipWhitelist.blockIP) {
            window.ipWhitelist.blockIP(ip, `Blocage automatique: ${reason}`, attackDetectionConfig.actions.autoBlockDuration);
        }
        
        // Journaliser le blocage si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.WARNING,
                details: `IP ${ip} bloquée automatiquement: ${reason}`,
                source: 'attack-detection',
                ipAddress: ip,
                metadata: {
                    reason: reason,
                    duration: `${attackDetectionConfig.actions.autoBlockDuration} minutes`,
                    expiresAt: expirationTime.toISOString()
                }
            });
        }
        
        return true;
    } catch (error) {
        console.error(`Erreur lors du blocage de l'IP ${ip}:`, error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: `Erreur lors du blocage de l'IP ${ip}: ${error.message}`,
                source: 'attack-detection',
                ipAddress: ip
            });
        }
        
        return false;
    }
}

/**
 * Envoie une notification pour une alerte
 * @param {Object} alert - Alerte à notifier
 */
function sendAlertNotification(alert) {
    // Dans un environnement réel, cette fonction enverrait une notification
    // par email, SMS, webhook, etc.
    console.log(`[NOTIFICATION] Alerte de sécurité: ${alert.details}`);
    
    // Simuler l'envoi d'une notification
    if (window.Notification && Notification.permission === 'granted') {
        new Notification('Alerte de sécurité Tech Shield', {
            body: alert.details,
            icon: '/logo.png'
        });
    }
}

/**
 * Obtient toutes les alertes d'attaques
 * @returns {Array} - Liste des alertes
 */
function getAllAttackAlerts() {
    return [...attackAlerts];
}

/**
 * Obtient les alertes d'attaques filtrées
 * @param {Object} filters - Filtres à appliquer
 * @returns {Array} - Liste des alertes filtrées
 */
function getFilteredAttackAlerts(filters = {}) {
    let filteredAlerts = [...attackAlerts];
    
    // Filtrer par type
    if (filters.type) {
        filteredAlerts = filteredAlerts.filter(alert => alert.type === filters.type);
    }
    
    // Filtrer par sévérité
    if (filters.severity) {
        filteredAlerts = filteredAlerts.filter(alert => alert.severity === filters.severity);
    }
    
    // Filtrer par source (IP)
    if (filters.source) {
        filteredAlerts = filteredAlerts.filter(alert => alert.source === filters.source);
    }
    
    // Filtrer par date
    if (filters.startDate) {
        const startDate = new Date(filters.startDate);
        filteredAlerts = filteredAlerts.filter(alert => new Date(alert.timestamp) >= startDate);
    }
    
    if (filters.endDate) {
        const endDate = new Date(filters.endDate);
        filteredAlerts = filteredAlerts.filter(alert => new Date(alert.timestamp) <= endDate);
    }
    
    return filteredAlerts;
}

/**
 * Obtient les IPs bloquées automatiquement
 * @returns {Object} - Liste des IPs bloquées
 */
function getAutoBlockedIPs() {
    // Nettoyer les IPs dont le blocage a expiré
    cleanExpiredIPBlocks();
    
    return {...autoBlockedIPs};
}

/**
 * Nettoie les blocages d'IP expirés
 */
function cleanExpiredIPBlocks() {
    const now = new Date();
    
    // Parcourir toutes les IPs bloquées
    for (const ip in autoBlockedIPs) {
        // Vérifier si le blocage a expiré
        if (new Date(autoBlockedIPs[ip].expiresAt) <= now) {
            // Supprimer l'IP de la liste des IPs bloquées
            delete autoBlockedIPs[ip];
            
            console.log(`Blocage de l'IP ${ip} expiré et supprimé`);
            
            // Journaliser la suppression si le module de logs est disponible
            if (window.securityLogs) {
                window.securityLogs.addLog({
                    status: window.securityLogs.LOG_TYPES.INFO,
                    details: `Blocage de l'IP ${ip} expiré et supprimé`,
                    source: 'attack-detection',
                    ipAddress: ip
                });
            }
        }
    }
}

/**
 * Débloque une adresse IP bloquée automatiquement
 * @param {string} ip - Adresse IP à débloquer
 * @returns {boolean} - Succès du déblocage
 */
function unblockIP(ip) {
    try {
        // Vérifier si l'IP est bloquée
        if (!autoBlockedIPs[ip]) {
            console.log(`L'IP ${ip} n'est pas bloquée`);
            return false;
        }
        
        // Supprimer l'IP de la liste des IPs bloquées
        delete autoBlockedIPs[ip];
        
        console.log(`IP ${ip} débloquée manuellement`);
        
        // Utiliser le module de liste blanche si disponible
        if (window.ipWhitelist && window.ipWhitelist.unblockIP) {
            window.ipWhitelist.unblockIP(ip);
        }
        
        // Journaliser le déblocage si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: `IP ${ip} débloquée manuellement`,
                source: 'attack-detection',
                ipAddress: ip
            });
        }
        
        return true;
    } catch (error) {
        console.error(`Erreur lors du déblocage de l'IP ${ip}:`, error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: `Erreur lors du déblocage de l'IP ${ip}: ${error.message}`,
                source: 'attack-detection',
                ipAddress: ip
            });
        }
        
        return false;
    }
}

// Exposer les fonctions publiques
window.attackDetection = {
    init: initAttackDetection,
    analyze: analyzeSecurityLogs,
    startAnalysis: startPeriodicAnalysis,
    stopAnalysis: stopPeriodicAnalysis,
    getAlerts: getAllAttackAlerts,
    getFilteredAlerts: getFilteredAttackAlerts,
    getBlockedIPs: getAutoBlockedIPs,
    blockIP: blockIP,
    unblockIP: unblockIP
};