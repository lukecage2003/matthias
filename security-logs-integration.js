// Module d'intégration des logs de sécurité avec les systèmes SIEM (ELK, Splunk)

// Configuration de l'intégration SIEM
const siemIntegrationConfig = {
    // Activer l'intégration SIEM
    enabled: true,
    
    // Type d'intégration (elk, splunk, graylog)
    type: 'elk',
    
    // Configuration spécifique à ELK
    elk: {
        // URL du serveur Elasticsearch (dans un environnement réel)
        serverUrl: 'http://localhost:9200',
        
        // Index pour les logs de sécurité
        indexName: 'techshield-security-logs',
        
        // Format des données
        dataFormat: 'json',
        
        // Intervalle de synchronisation (en minutes)
        syncInterval: 5
    },
    
    // Configuration spécifique à Splunk
    splunk: {
        // URL du collecteur HTTP (dans un environnement réel)
        collectorUrl: 'http://localhost:8088',
        
        // Token d'authentification (à remplacer par un vrai token dans un environnement réel)
        token: 'YOUR_SPLUNK_TOKEN',
        
        // Source des événements
        source: 'techshield-security',
        
        // Type d'événement
        sourcetype: 'techshield:security:logs'
    },
    
    // Configuration spécifique à Graylog
    graylog: {
        // URL du serveur Graylog (dans un environnement réel)
        serverUrl: 'http://localhost:12201',
        
        // Format des données (GELF)
        dataFormat: 'gelf',
        
        // Facility
        facility: 'techshield-security'
    },
    
    // Configuration des champs à inclure dans les logs
    fields: {
        // Champs standard
        standard: ['timestamp', 'email', 'ipAddress', 'status', 'details'],
        
        // Champs étendus
        extended: ['userAgent', 'geoLocation', 'deviceInfo'],
        
        // Champs personnalisés
        custom: []
    },
    
    // Configuration de la mise en forme des logs
    formatting: {
        // Format de date
        dateFormat: 'ISO8601',
        
        // Inclure les métadonnées
        includeMetadata: true,
        
        // Niveau de détail (1: minimal, 2: standard, 3: détaillé)
        verbosity: 2
    }
};

// Fonction pour formater un log au format ELK
function formatLogForELK(log) {
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
            'level': getLogLevel(log.status)
        },
        'techshield': {
            'application': 'web-security',
            'environment': 'production'
        }
    };
}

// Fonction pour formater un log au format Splunk
function formatLogForSplunk(log) {
    return {
        'time': new Date(log.timestamp).getTime() / 1000,
        'host': window.location.hostname,
        'source': siemIntegrationConfig.splunk.source,
        'sourcetype': siemIntegrationConfig.splunk.sourcetype,
        'event': {
            'timestamp': log.timestamp,
            'user': log.email || 'unknown',
            'ip': log.ipAddress,
            'status': log.status,
            'details': log.details,
            'level': getLogLevel(log.status),
            'application': 'techshield-web-security'
        }
    };
}

// Fonction pour formater un log au format GELF (Graylog)
function formatLogForGraylog(log) {
    return {
        'version': '1.1',
        'host': window.location.hostname,
        'short_message': `${log.status.toUpperCase()}: ${log.details}`,
        'full_message': JSON.stringify(log),
        'timestamp': new Date(log.timestamp).getTime() / 1000,
        'level': getNumericLogLevel(log.status),
        '_user': log.email || 'unknown',
        '_ip_address': log.ipAddress,
        '_status': log.status,
        '_facility': siemIntegrationConfig.graylog.facility
    };
}

// Fonction pour obtenir le niveau de log textuel
function getLogLevel(status) {
    if (!window.securityLogs) return 'info';
    
    return status === window.securityLogs.LOG_TYPES.SUCCESS ? 'info' :
           status === window.securityLogs.LOG_TYPES.FAILURE ? 'error' :
           status === window.securityLogs.LOG_TYPES.SUSPICIOUS ? 'warning' :
           status === window.securityLogs.LOG_TYPES.WARNING ? 'warning' :
           status === window.securityLogs.LOG_TYPES.CRITICAL ? 'critical' : 'info';
}

// Fonction pour obtenir le niveau de log numérique (pour GELF)
function getNumericLogLevel(status) {
    if (!window.securityLogs) return 6; // Info
    
    return status === window.securityLogs.LOG_TYPES.SUCCESS ? 6 : // Info
           status === window.securityLogs.LOG_TYPES.FAILURE ? 3 : // Error
           status === window.securityLogs.LOG_TYPES.SUSPICIOUS ? 4 : // Warning
           status === window.securityLogs.LOG_TYPES.WARNING ? 4 : // Warning
           status === window.securityLogs.LOG_TYPES.CRITICAL ? 2 : 6; // Critical : Info
}

// Fonction pour exporter les logs au format compatible avec ELK
function exportLogsForELK() {
    if (!window.securityLogs) {
        console.error('Le module de journalisation de sécurité n\'est pas disponible');
        return [];
    }
    
    const logs = window.securityLogs.getAllLogs();
    return logs.map(log => formatLogForELK(log));
}

// Fonction pour exporter les logs au format compatible avec Splunk
function exportLogsForSplunk() {
    if (!window.securityLogs) {
        console.error('Le module de journalisation de sécurité n\'est pas disponible');
        return [];
    }
    
    const logs = window.securityLogs.getAllLogs();
    return logs.map(log => formatLogForSplunk(log));
}

// Fonction pour exporter les logs au format compatible avec Graylog
function exportLogsForGraylog() {
    if (!window.securityLogs) {
        console.error('Le module de journalisation de sécurité n\'est pas disponible');
        return [];
    }
    
    const logs = window.securityLogs.getAllLogs();
    return logs.map(log => formatLogForGraylog(log));
}

// Fonction pour télécharger les logs au format compatible avec le SIEM sélectionné
function downloadLogsForSIEM(siemType = siemIntegrationConfig.type) {
    let logs = [];
    let fileName = '';
    
    switch(siemType.toLowerCase()) {
        case 'elk':
            logs = exportLogsForELK();
            fileName = 'techshield-security-logs-elk.json';
            break;
        case 'splunk':
            logs = exportLogsForSplunk();
            fileName = 'techshield-security-logs-splunk.json';
            break;
        case 'graylog':
            logs = exportLogsForGraylog();
            fileName = 'techshield-security-logs-graylog.json';
            break;
        default:
            logs = exportLogsForELK(); // Par défaut, utiliser ELK
            fileName = 'techshield-security-logs-siem.json';
    }
    
    // Créer un objet Blob avec le contenu
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    
    // Créer un URL pour le blob
    const url = URL.createObjectURL(blob);
    
    // Créer un élément a pour le téléchargement
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    
    // Ajouter l'élément au DOM, cliquer dessus, puis le supprimer
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    // Libérer l'URL
    URL.revokeObjectURL(url);
    
    return true;
}

// Fonction pour simuler l'envoi des logs à un serveur SIEM
function sendLogsToSIEM(siemType = siemIntegrationConfig.type) {
    // Dans un environnement réel, cette fonction enverrait les logs au serveur SIEM
    // Pour cette démonstration, nous simulons l'envoi
    
    let logs = [];
    let endpoint = '';
    
    switch(siemType.toLowerCase()) {
        case 'elk':
            logs = exportLogsForELK();
            endpoint = siemIntegrationConfig.elk.serverUrl + '/' + siemIntegrationConfig.elk.indexName + '/_doc';
            break;
        case 'splunk':
            logs = exportLogsForSplunk();
            endpoint = siemIntegrationConfig.splunk.collectorUrl + '/services/collector/event';
            break;
        case 'graylog':
            logs = exportLogsForGraylog();
            endpoint = siemIntegrationConfig.graylog.serverUrl;
            break;
        default:
            logs = exportLogsForELK(); // Par défaut, utiliser ELK
            endpoint = siemIntegrationConfig.elk.serverUrl + '/' + siemIntegrationConfig.elk.indexName + '/_doc';
    }
    
    console.log(`Simulation d'envoi de ${logs.length} logs à ${siemType} (${endpoint})`);
    console.log('Logs:', logs);
    
    // Simuler une réponse réussie
    return {
        success: true,
        sent: logs.length,
        timestamp: new Date().toISOString()
    };
}

// Fonction pour configurer l'intégration SIEM
function configureSIEMIntegration(config) {
    // Fusionner la configuration fournie avec la configuration existante
    Object.assign(siemIntegrationConfig, config);
    
    return siemIntegrationConfig;
}

// Fonction pour obtenir la configuration actuelle
function getSIEMIntegrationConfig() {
    return siemIntegrationConfig;
}

// Fonction pour initialiser l'interface utilisateur d'intégration SIEM
function initSIEMIntegrationUI() {
    const siemContainer = document.getElementById('siemIntegration');
    if (!siemContainer) return;
    
    // Créer l'interface utilisateur
    siemContainer.innerHTML = `
        <div class="siem-config-panel">
            <h3>Intégration SIEM</h3>
            
            <div class="form-group">
                <label for="siemType">Type de SIEM:</label>
                <select id="siemType" class="form-control">
                    <option value="elk" ${siemIntegrationConfig.type === 'elk' ? 'selected' : ''}>ELK Stack</option>
                    <option value="splunk" ${siemIntegrationConfig.type === 'splunk' ? 'selected' : ''}>Splunk</option>
                    <option value="graylog" ${siemIntegrationConfig.type === 'graylog' ? 'selected' : ''}>Graylog</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="siemEnabled">Activer l'intégration:</label>
                <input type="checkbox" id="siemEnabled" ${siemIntegrationConfig.enabled ? 'checked' : ''}>
            </div>
            
            <div class="siem-actions">
                <button id="exportSIEMLogs" class="btn btn-primary">Exporter les logs</button>
                <button id="sendSIEMLogs" class="btn btn-secondary">Simuler l'envoi</button>
            </div>
        </div>
        
        <div class="siem-status-panel">
            <h3>Statut de l'intégration</h3>
            <div id="siemStatus" class="${siemIntegrationConfig.enabled ? 'status-enabled' : 'status-disabled'}">
                ${siemIntegrationConfig.enabled ? 'Activé' : 'Désactivé'}
            </div>
            <div id="lastSyncInfo">Dernière synchronisation: Jamais</div>
        </div>
    `;
    
    // Ajouter les gestionnaires d'événements
    document.getElementById('siemType').addEventListener('change', function() {
        siemIntegrationConfig.type = this.value;
        updateSIEMUI();
    });
    
    document.getElementById('siemEnabled').addEventListener('change', function() {
        siemIntegrationConfig.enabled = this.checked;
        updateSIEMUI();
    });
    
    document.getElementById('exportSIEMLogs').addEventListener('click', function() {
        downloadLogsForSIEM(siemIntegrationConfig.type);
    });
    
    document.getElementById('sendSIEMLogs').addEventListener('click', function() {
        const result = sendLogsToSIEM(siemIntegrationConfig.type);
        if (result.success) {
            document.getElementById('lastSyncInfo').textContent = `Dernière synchronisation: ${new Date().toLocaleString()} (${result.sent} logs)`;
            showNotification(`${result.sent} logs envoyés avec succès à ${siemIntegrationConfig.type.toUpperCase()}`, 'success');
        } else {
            showNotification(`Erreur lors de l'envoi des logs à ${siemIntegrationConfig.type.toUpperCase()}`, 'error');
        }
    });
}

// Fonction pour mettre à jour l'interface utilisateur SIEM
function updateSIEMUI() {
    const siemStatus = document.getElementById('siemStatus');
    if (siemStatus) {
        siemStatus.className = siemIntegrationConfig.enabled ? 'status-enabled' : 'status-disabled';
        siemStatus.textContent = siemIntegrationConfig.enabled ? 'Activé' : 'Désactivé';
    }
}

// Fonction pour afficher une notification
function showNotification(message, type = 'info') {
    // Vérifier si la fonction existe déjà dans le contexte global
    if (window.showNotification) {
        window.showNotification(message, type);
        return;
    }
    
    // Créer l'élément de notification
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Ajouter la notification au document
    const notificationsContainer = document.querySelector('.notifications-container');
    if (notificationsContainer) {
        notificationsContainer.appendChild(notification);
    } else {
        // Créer un conteneur si nécessaire
        const container = document.createElement('div');
        container.className = 'notifications-container';
        container.appendChild(notification);
        document.body.appendChild(container);
    }
    
    // Supprimer la notification après un délai
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 5000);
}

// Fonction pour améliorer les logs de sécurité existants avec des informations supplémentaires
function enhanceSecurityLog(log) {
    // Ajouter des informations supplémentaires au log
    const enhancedLog = { ...log };
    
    // Ajouter l'agent utilisateur si disponible
    if (navigator && navigator.userAgent) {
        enhancedLog.userAgent = navigator.userAgent;
    }
    
    // Ajouter des informations sur l'appareil
    enhancedLog.deviceInfo = {
        screenWidth: window.screen.width,
        screenHeight: window.screen.height,
        colorDepth: window.screen.colorDepth,
        platform: navigator.platform,
        language: navigator.language
    };
    
    // Dans un environnement réel, on pourrait ajouter des informations de géolocalisation
    // via un service tiers, mais pour cette démonstration, nous simulons ces données
    enhancedLog.geoLocation = {
        country: 'France',
        city: 'Paris',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    
    return enhancedLog;
}

// Fonction pour surveiller les tentatives de connexion échouées et déclencher des alertes
function monitorFailedLoginAttempts() {
    if (!window.securityLogs) return;
    
    // S'abonner aux événements de connexion
    const loginEventIndex = window.securityLogs.subscribeToLoginEvents(function(log) {
        // Vérifier si c'est une tentative échouée
        if (log.status === window.securityLogs.LOG_TYPES.FAILURE) {
            // Obtenir les logs récents pour cette adresse IP
            const ipLogs = window.securityLogs.getLogsByIP(log.ipAddress);
            const recentFailedLogs = ipLogs.filter(l => 
                l.status === window.securityLogs.LOG_TYPES.FAILURE && 
                new Date(l.timestamp) >= new Date(Date.now() - 15 * 60 * 1000) // 15 minutes
            );
            
            // Si 5 tentatives échouées ou plus, déclencher une alerte
            if (recentFailedLogs.length >= 5) {
                // Créer une alerte de sécurité
                const alert = window.securityLogs.createSecurityAlert(
                    log.ipAddress,
                    `5 tentatives de connexion échouées détectées pour l'adresse IP ${log.ipAddress}`,
                    window.securityLogs.LOG_TYPES.SUSPICIOUS
                );
                
                // Bloquer temporairement l'IP
                window.securityLogs.blockIP(log.ipAddress, 30); // 30 minutes
                
                // Envoyer l'alerte au SIEM si l'intégration est activée
                if (siemIntegrationConfig.enabled) {
                    const enhancedLog = enhanceSecurityLog(log);
                    sendLogsToSIEM(siemIntegrationConfig.type);
                }
            }
        }
    });
    
    return loginEventIndex;
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.siemIntegration = {
    // Configuration
    getConfig: getSIEMIntegrationConfig,
    configure: configureSIEMIntegration,
    
    // Exportation des logs
    exportForELK: exportLogsForELK,
    exportForSplunk: exportLogsForSplunk,
    exportForGraylog: exportLogsForGraylog,
    downloadLogs: downloadLogsForSIEM,
    
    // Envoi des logs
    sendLogs: sendLogsToSIEM,
    
    // Interface utilisateur
    initUI: initSIEMIntegrationUI,
    updateUI: updateSIEMUI,
    
    // Surveillance et alertes
    monitorFailedLogins: monitorFailedLoginAttempts,
    enhanceLog: enhanceSecurityLog
};

// Initialiser la surveillance des tentatives de connexion échouées
document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si le module de logs de sécurité est disponible
    if (window.securityLogs) {
        // Démarrer la surveillance des tentatives de connexion échouées
        monitorFailedLoginAttempts();
        
        // Initialiser l'interface utilisateur d'intégration SIEM si on est sur la page d'administration
        if (document.querySelector('.admin-container')) {
            initSIEMIntegrationUI();
        }
    }
});