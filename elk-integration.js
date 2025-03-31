// Module d'intégration ELK Stack pour Tech Shield
// Ce module permet d'envoyer les logs de sécurité vers un système ELK Stack pour analyse avancée

/**
 * Configuration de l'intégration ELK Stack
 */
const elkConfig = {
    // URL du serveur Elasticsearch (à configurer selon l'environnement)
    elasticsearchUrl: 'https://elasticsearch.example.com:9200',
    
    // Index pour les logs de sécurité
    securityIndex: 'tech-shield-security-logs',
    
    // Index pour les alertes
    alertsIndex: 'tech-shield-security-alerts',
    
    // Intervalle d'envoi des logs en batch (en secondes)
    batchInterval: 60,
    
    // Taille maximale du batch (nombre de logs)
    batchSize: 50,
    
    // Activer le mode simulation (pas d'envoi réel vers ELK)
    simulationMode: true,
    
    // Niveau de log minimum à envoyer vers ELK
    minLogLevel: 'warning', // 'info', 'warning', 'suspicious', 'critical'
    
    // Activer la compression des données
    enableCompression: true,
    
    // Timeout pour les requêtes (en ms)
    requestTimeout: 5000,
    
    // Nombre de tentatives en cas d'échec
    retryAttempts: 3,
    
    // Délai entre les tentatives (en ms)
    retryDelay: 1000
};

// File d'attente des logs à envoyer
let logQueue = [];

// Timer pour l'envoi en batch
let batchTimer = null;

/**
 * Initialise le module d'intégration ELK
 */
function init() {
    console.log('Initialisation du module d\'intégration ELK Stack');
    
    // S'abonner aux événements de logs si le module de base est disponible
    if (window.securityLogs) {
        window.securityLogs.subscribeToLoginEvents(queueLogForELK);
        window.securityLogs.subscribeToAlertEvents(queueAlertForELK);
        console.log('Abonnement aux événements de logs et alertes réussi');
    } else {
        console.error('Module de logs de base non disponible, impossible d\'initialiser l\'intégration ELK');
        return false;
    }
    
    // Démarrer le timer pour l'envoi en batch
    startBatchTimer();
    
    return true;
}

/**
 * Démarre le timer pour l'envoi en batch
 */
function startBatchTimer() {
    if (batchTimer) {
        clearInterval(batchTimer);
    }
    
    batchTimer = setInterval(() => {
        if (logQueue.length > 0) {
            sendLogBatch();
        }
    }, elkConfig.batchInterval * 1000);
    
    console.log(`Timer d'envoi en batch démarré (intervalle: ${elkConfig.batchInterval}s)`);
}

/**
 * Ajoute un log à la file d'attente pour envoi vers ELK
 * @param {Object} log - Log à envoyer
 */
function queueLogForELK(log) {
    // Vérifier si le niveau de log est suffisant pour être envoyé
    if (!shouldSendLogLevel(log.status)) {
        return;
    }
    
    // Ajouter le log à la file d'attente
    logQueue.push({
        type: 'log',
        data: formatLogForELK(log),
        timestamp: new Date().toISOString()
    });
    
    // Si la taille du batch est atteinte, envoyer immédiatement
    if (logQueue.length >= elkConfig.batchSize) {
        sendLogBatch();
    }
}

/**
 * Ajoute une alerte à la file d'attente pour envoi vers ELK
 * @param {Object} alert - Alerte à envoyer
 */
function queueAlertForELK(alert) {
    // Ajouter l'alerte à la file d'attente
    logQueue.push({
        type: 'alert',
        data: formatAlertForELK(alert),
        timestamp: new Date().toISOString()
    });
    
    // Les alertes sont toujours envoyées immédiatement
    sendLogBatch();
}

/**
 * Vérifie si un niveau de log doit être envoyé vers ELK
 * @param {string} logLevel - Niveau de log à vérifier
 * @returns {boolean} True si le log doit être envoyé
 */
function shouldSendLogLevel(logLevel) {
    const levels = {
        'info': 0,
        'success': 1,
        'warning': 2,
        'suspicious': 3,
        'failure': 3,
        'critical': 4
    };
    
    const minLevel = levels[elkConfig.minLogLevel] || 0;
    const currentLevel = levels[logLevel] || 0;
    
    return currentLevel >= minLevel;
}

/**
 * Formate un log pour l'envoi vers ELK
 * @param {Object} log - Log à formater
 * @returns {Object} Log formaté pour ELK
 */
function formatLogForELK(log) {
    return {
        '@timestamp': log.timestamp,
        'event': {
            'kind': 'event',
            'category': 'security',
            'type': log.status,
            'severity': getSeverityLevel(log.status)
        },
        'user': {
            'name': log.email,
            'id': hashEmail(log.email)
        },
        'source': {
            'ip': log.ipAddress,
            'user_agent': log.userAgent
        },
        'message': log.details,
        'tech_shield': {
            'log_id': log.id,
            'metadata': log.metadata || {},
            'geo_location': log.geoLocation || null
        }
    };
}

/**
 * Formate une alerte pour l'envoi vers ELK
 * @param {Object} alert - Alerte à formater
 * @returns {Object} Alerte formatée pour ELK
 */
function formatAlertForELK(alert) {
    return {
        '@timestamp': alert.timestamp,
        'event': {
            'kind': 'alert',
            'category': 'security',
            'type': alert.severity,
            'severity': getSeverityLevel(alert.severity)
        },
        'user': {
            'name': alert.email,
            'id': hashEmail(alert.email)
        },
        'source': {
            'ip': alert.ipAddress
        },
        'message': alert.description,
        'tech_shield': {
            'alert_id': alert.id,
            'alert_title': alert.title,
            'alert_status': alert.status,
            'metadata': alert.metadata || {}
        }
    };
}

/**
 * Obtient le niveau de sévérité numérique pour un type de log
 * @param {string} logType - Type de log
 * @returns {number} Niveau de sévérité (0-4)
 */
function getSeverityLevel(logType) {
    switch (logType) {
        case 'success':
        case 'info':
            return 0; // Informational
        case 'warning':
            return 1; // Warning
        case 'suspicious':
        case 'failure':
            return 2; // Error
        case 'critical':
            return 3; // Critical
        default:
            return 0;
    }
}

/**
 * Crée un hash simple d'une adresse email pour anonymisation
 * @param {string} email - Email à hasher
 * @returns {string} Hash de l'email
 */
function hashEmail(email) {
    if (!email) return 'unknown';
    
    // Implémentation simple de hachage pour la démonstration
    // Dans un environnement de production, utiliser une fonction de hachage cryptographique
    let hash = 0;
    for (let i = 0; i < email.length; i++) {
        const char = email.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Conversion en entier 32 bits
    }
    return 'user_' + Math.abs(hash).toString(16);
}

/**
 * Envoie un batch de logs vers ELK
 */
function sendLogBatch() {
    if (logQueue.length === 0) return;
    
    // Copier la file d'attente et la vider
    const batch = [...logQueue];
    logQueue = [];
    
    // En mode simulation, juste afficher les logs
    if (elkConfig.simulationMode) {
        console.log(`[ELK Simulation] Envoi de ${batch.length} logs/alertes vers ELK Stack:`);
        console.log(batch);
        return;
    }
    
    // Préparer les données pour l'envoi
    const logs = batch.filter(item => item.type === 'log').map(item => item.data);
    const alerts = batch.filter(item => item.type === 'alert').map(item => item.data);
    
    // Envoyer les logs
    if (logs.length > 0) {
        sendToElasticsearch(elkConfig.securityIndex, logs)
            .then(result => {
                console.log(`Logs envoyés avec succès vers ELK (${logs.length} logs)`);
            })
            .catch(error => {
                console.error('Erreur lors de l\'envoi des logs vers ELK:', error);
                // Remettre les logs dans la file d'attente en cas d'échec
                logQueue = [...logQueue, ...batch.filter(item => item.type === 'log')];
            });
    }
    
    // Envoyer les alertes
    if (alerts.length > 0) {
        sendToElasticsearch(elkConfig.alertsIndex, alerts)
            .then(result => {
                console.log(`Alertes envoyées avec succès vers ELK (${alerts.length} alertes)`);
            })
            .catch(error => {
                console.error('Erreur lors de l\'envoi des alertes vers ELK:', error);
                // Remettre les alertes dans la file d'attente en cas d'échec
                logQueue = [...logQueue, ...batch.filter(item => item.type === 'alert')];
            });
    }
}

/**
 * Envoie des données vers Elasticsearch
 * @param {string} index - Index Elasticsearch
 * @param {Array} data - Données à envoyer
 * @returns {Promise} Promesse résolue après l'envoi
 */
function sendToElasticsearch(index, data) {
    // Cette fonction simule l'envoi vers Elasticsearch
    // Dans un environnement de production, utiliser fetch ou une bibliothèque HTTP
    return new Promise((resolve, reject) => {
        // Simuler une requête réseau
        setTimeout(() => {
            // Simuler une réussite dans 90% des cas
            if (Math.random() < 0.9) {
                resolve({ status: 'success', count: data.length });
            } else {
                reject(new Error('Erreur de connexion à Elasticsearch'));
            }
        }, 500);
    });
}

/**
 * Arrête le module d'intégration ELK
 */
function stop() {
    // Arrêter le timer
    if (batchTimer) {
        clearInterval(batchTimer);
        batchTimer = null;
    }
    
    // Envoyer les logs restants
    if (logQueue.length > 0) {
        sendLogBatch();
    }
    
    // Se désabonner des événements
    if (window.securityLogs) {
        window.securityLogs.unsubscribeFromLoginEvents(queueLogForELK);
        window.securityLogs.unsubscribeFromAlertEvents(queueAlertForELK);
    }
    
    console.log('Module d\'intégration ELK arrêté');
}

// Exposer les fonctions publiques
window.elkIntegration = {
    init,
    stop,
    getConfig: () => ({ ...elkConfig }),
    setConfig: (newConfig) => {
        Object.assign(elkConfig, newConfig);
        // Redémarrer le timer si l'intervalle a changé
        if (batchTimer) {
            startBatchTimer();
        }
    },
    getQueueStatus: () => ({
        queueLength: logQueue.length,
        batchSize: elkConfig.batchSize,
        nextSendIn: batchTimer ? Math.ceil((elkConfig.batchInterval * 1000 - (Date.now() % (elkConfig.batchInterval * 1000))) / 1000) : 0
    }),
    flushQueue: sendLogBatch
};

// Initialiser automatiquement si le document est déjà chargé
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(init, 1000);
} else {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 1000));
}