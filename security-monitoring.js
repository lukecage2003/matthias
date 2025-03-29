// Module principal de surveillance de sécurité pour Tech Shield
// Intègre la journalisation, les alertes et l'exportation SIEM

document.addEventListener('DOMContentLoaded', function() {
    console.log('Initialisation du système de surveillance de sécurité...');
    
    // Vérifier si les modules de sécurité sont disponibles
    const securityModulesAvailable = {
        securityLogs: !!window.securityLogs,
        advancedSecurityLogs: !!window.advancedSecurityLogs,
        siemIntegration: !!window.siemIntegration,
        securityAlertSystem: !!window.securityAlertSystem
    };
    
    // Initialiser le système de surveillance
    initSecurityMonitoring(securityModulesAvailable);
});

// Configuration du système de surveillance
const securityMonitoringConfig = {
    // Intervalle de vérification des logs (en millisecondes)
    checkInterval: 60000, // 1 minute
    
    // Nombre maximum de tentatives échouées avant alerte
    maxFailedAttempts: 5,
    
    // Fenêtre de temps pour les tentatives (en minutes)
    timeWindowMinutes: 15,
    
    // Activer la notification par email (simulation)
    enableEmailNotification: true,
    
    // Adresses email des administrateurs (dans un environnement réel)
    adminEmails: ['admin@techshield.com'],
    
    // Configuration de l'exportation SIEM
    siemExport: {
        // Activer l'exportation automatique
        enabled: true,
        
        // Intervalle d'exportation (en millisecondes)
        exportInterval: 3600000, // 1 heure
        
        // Type de SIEM par défaut
        defaultType: 'elk'
    },
    
    // Configuration de la rétention des logs
    logRetention: {
        // Durée de conservation des logs (en jours)
        days: 90,
        
        // Nombre maximum de logs à conserver
        maxEntries: 10000,
        
        // Purger automatiquement les anciens logs
        autoPurge: true,
        
        // Intervalle de purge (en millisecondes)
        purgeInterval: 86400000 // 24 heures
    }
};

// Fonction pour initialiser le système de surveillance
function initSecurityMonitoring(availableModules) {
    console.log('Modules de sécurité disponibles:', availableModules);
    
    // Initialiser le système de journalisation si disponible
    if (availableModules.securityLogs) {
        console.log('Initialisation du système de journalisation...');
        
        // S'abonner aux événements de connexion
        const loginEventIndex = window.securityLogs.subscribeToLoginEvents(handleLoginEvent);
        console.log('Abonnement aux événements de connexion (index:', loginEventIndex, ')');
        
        // Configurer la purge automatique des logs
        if (securityMonitoringConfig.logRetention.autoPurge) {
            setInterval(purgeOldLogs, securityMonitoringConfig.logRetention.purgeInterval);
            console.log('Purge automatique des logs configurée');
        }
    }
    
    // Initialiser le système d'alerte si disponible
    if (availableModules.securityAlertSystem) {
        console.log('Initialisation du système d\'alerte...');
        window.securityAlertSystem.initAlertSystem();
    }
    
    // Initialiser l'intégration SIEM si disponible
    if (availableModules.siemIntegration && securityMonitoringConfig.siemExport.enabled) {
        console.log('Initialisation de l\'intégration SIEM...');
        
        // Configurer l'exportation automatique des logs
        setInterval(function() {
            exportLogsToSIEM(securityMonitoringConfig.siemExport.defaultType);
        }, securityMonitoringConfig.siemExport.exportInterval);
        
        console.log('Exportation automatique des logs configurée');
    }
    
    // Démarrer la vérification périodique des logs
    setInterval(checkSecurityLogs, securityMonitoringConfig.checkInterval);
    console.log('Vérification périodique des logs configurée');
    
    // Initialiser l'interface utilisateur si nous sommes sur la page d'administration
    if (document.querySelector('.admin-container')) {
        initMonitoringUI();
    }
}

// Fonction pour gérer les événements de connexion
function handleLoginEvent(log) {
    console.log('Événement de connexion détecté:', log);
    
    // Vérifier si c'est une tentative échouée
    if (log.status === window.securityLogs.LOG_TYPES.FAILURE) {
        // Vérifier si le seuil d'alertes est atteint
        checkFailedLoginThreshold(log);
    }
    
    // Enrichir le log avec des informations supplémentaires
    if (window.siemIntegration && window.siemIntegration.enhanceLog) {
        const enhancedLog = window.siemIntegration.enhanceLog(log);
        console.log('Log enrichi:', enhancedLog);
    }
}

// Fonction pour vérifier si le seuil de tentatives échouées est atteint
function checkFailedLoginThreshold(log) {
    // Si le système d'alerte est disponible, il s'en chargera
    if (window.securityAlertSystem) return;
    
    // Sinon, implémenter une vérification basique
    const ipLogs = window.securityLogs.getLogsByIP(log.ipAddress);
    const timeWindowAgo = new Date(Date.now() - securityMonitoringConfig.timeWindowMinutes * 60 * 1000);
    
    // Filtrer les tentatives échouées récentes
    const recentFailedLogs = ipLogs.filter(l => 
        l.status === window.securityLogs.LOG_TYPES.FAILURE && 
        new Date(l.timestamp) >= timeWindowAgo
    );
    
    // Si le seuil est atteint, créer une alerte
    if (recentFailedLogs.length >= securityMonitoringConfig.maxFailedAttempts) {
        console.warn(`Alerte: ${recentFailedLogs.length} tentatives de connexion échouées détectées pour l'IP ${log.ipAddress}`);
        
        // Créer une alerte si le module est disponible
        if (window.securityLogs.createSecurityAlert) {
            window.securityLogs.createSecurityAlert(
                log.ipAddress,
                `${recentFailedLogs.length} tentatives de connexion échouées détectées`,
                window.securityLogs.LOG_TYPES.SUSPICIOUS
            );
        }
        
        // Bloquer temporairement l'IP
        if (window.securityLogs.blockIP) {
            window.securityLogs.blockIP(log.ipAddress, 30); // 30 minutes
        }
        
        // Envoyer une notification par email (simulation)
        if (securityMonitoringConfig.enableEmailNotification) {
            sendSecurityAlert({
                type: 'failed_login_threshold',
                severity: 'high',
                ipAddress: log.ipAddress,
                email: log.email,
                details: `${recentFailedLogs.length} tentatives de connexion échouées détectées dans les dernières ${securityMonitoringConfig.timeWindowMinutes} minutes`,
                timestamp: new Date().toISOString()
            });
        }
    }
}

// Fonction pour vérifier périodiquement les logs de sécurité
function checkSecurityLogs() {
    if (!window.securityLogs) return;
    
    const logs = window.securityLogs.getAllLogs();
    const activeAlerts = window.securityLogs.getActiveAlerts ? window.securityLogs.getActiveAlerts() : [];
    
    console.log(`Vérification des logs: ${logs.length} logs, ${activeAlerts.length} alertes actives`);
    
    // Vérifier les comportements suspects si le module avancé est disponible
    if (window.advancedSecurityLogs) {
        // Obtenir la liste des utilisateurs uniques
        const uniqueUsers = [...new Set(logs.map(log => log.email).filter(Boolean))];
        
        // Vérifier chaque utilisateur
        uniqueUsers.forEach(email => {
            const suspiciousActivities = window.advancedSecurityLogs.detectSuspiciousActivity(email);
            
            if (suspiciousActivities.length > 0) {
                console.warn(`Activités suspectes détectées pour ${email}:`, suspiciousActivities);
                
                // Notifier l'administrateur
                if (window.advancedSecurityLogs.notifyAdmin) {
                    window.advancedSecurityLogs.notifyAdmin(suspiciousActivities);
                }
            }
        });
    }
}

// Fonction pour purger les anciens logs
function purgeOldLogs() {
    if (!window.securityLogs) return;
    
    const logs = window.securityLogs.getAllLogs();
    
    // Vérifier si le nombre de logs dépasse la limite
    if (logs.length > securityMonitoringConfig.logRetention.maxEntries) {
        console.log(`Purge des logs: ${logs.length} logs, limite: ${securityMonitoringConfig.logRetention.maxEntries}`);
        
        // Trier les logs par date (les plus anciens en premier)
        const sortedLogs = [...logs].sort((a, b) => 
            new Date(a.timestamp) - new Date(b.timestamp)
        );
        
        // Calculer le nombre de logs à supprimer
        const logsToRemove = logs.length - securityMonitoringConfig.logRetention.maxEntries;
        
        // Supprimer les logs les plus anciens
        const oldestLogs = sortedLogs.slice(0, logsToRemove);
        
        console.log(`Suppression de ${logsToRemove} logs anciens`);
        
        // Dans un environnement réel, on supprimerait ces logs de la base de données
        // Pour cette démonstration, nous simulons la suppression
        
        // Ajouter un log pour indiquer la purge
        if (window.securityLogs.addLoginLog) {
            window.securityLogs.addLoginLog(
                'système',
                'N/A',
                window.securityLogs.LOG_TYPES.INFO,
                `Purge automatique: ${logsToRemove} logs supprimés`
            );
        }
    }
    
    // Vérifier si des logs sont plus anciens que la durée de conservation
    if (securityMonitoringConfig.logRetention.days > 0) {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - securityMonitoringConfig.logRetention.days);
        
        const oldLogs = logs.filter(log => new Date(log.timestamp) < cutoffDate);
        
        if (oldLogs.length > 0) {
            console.log(`${oldLogs.length} logs plus anciens que ${securityMonitoringConfig.logRetention.days} jours`);
            
            // Dans un environnement réel, on supprimerait ces logs de la base de données
            // Pour cette démonstration, nous simulons la suppression
            
            // Ajouter un log pour indiquer la purge
            if (window.securityLogs.addLoginLog) {
                window.securityLogs.addLoginLog(
                    'système',
                    'N/A',
                    window.securityLogs.LOG_TYPES.INFO,
                    `Purge automatique: ${oldLogs.length} logs plus anciens que ${securityMonitoringConfig.logRetention.days} jours supprimés`
                );
            }
        }
    }
}

// Fonction pour exporter les logs vers un SIEM
function exportLogsToSIEM(siemType) {
    if (!window.siemIntegration || !window.securityLogs) return;
    
    console.log(`Exportation des logs vers ${siemType}...`);
    
    // Obtenir tous les logs
    const logs = window.securityLogs.getAllLogs();
    
    // Exporter les logs
    if (window.siemIntegration.sendLogs) {
        const result = window.siemIntegration.sendLogs(siemType);
        
        console.log(`Exportation terminée: ${result.sent} logs envoyés à ${siemType}`);
        
        // Ajouter un log pour indiquer l'exportation
        if (window.securityLogs.addLoginLog) {
            window.securityLogs.addLoginLog(
                'système',
                'N/A',
                window.securityLogs.LOG_TYPES.INFO,
                `Exportation SIEM: ${result.sent} logs envoyés à ${siemType}`
            );
        }
        
        return result;
    }
    
    return { success: false, reason: 'Fonction d\'envoi non disponible' };
}

// Fonction pour envoyer une alerte de sécurité par email (simulation)
function sendSecurityAlert(alert) {
    // Dans un environnement réel, cette fonction enverrait un email
    // Pour cette démonstration, nous simulons l'envoi
    console.log(`Simulation d'envoi d'alerte de sécurité:`, {
        to: securityMonitoringConfig.adminEmails,
        subject: `Alerte de sécurité (${alert.severity}): ${alert.type}`,
        body: `
            Une alerte de sécurité a été détectée:
            
            Type: ${alert.type}
            Gravité: ${alert.severity}
            Détails: ${alert.details}
            ${alert.email ? `Utilisateur: ${alert.email}` : ''}
            ${alert.ipAddress ? `IP: ${alert.ipAddress}` : ''}
            Date: ${new Date(alert.timestamp).toLocaleString()}
            
            Veuillez vous connecter au tableau de bord d'administration pour plus de détails.
        `
    });
    
    return true;
}

// Fonction pour initialiser l'interface utilisateur du système de surveillance
function initMonitoringUI() {
    const monitoringContainer = document.getElementById('securityMonitoring');
    if (!monitoringContainer) return;
    
    // Créer l'interface utilisateur
    monitoringContainer.innerHTML = `
        <div class="monitoring-panel">
            <h3>Surveillance de sécurité</h3>
            
            <div class="monitoring-stats">
                <div class="stat-card">
                    <div class="stat-value" id="totalLogsCount">0</div>
                    <div class="stat-label">Logs totaux</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value" id="failedLoginsCount">0</div>
                    <div class="stat-label">Connexions échouées</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value" id="activeAlertsCount">0</div>
                    <div class="stat-label">Alertes actives</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value" id="blockedIPsCount">0</div>
                    <div class="stat-label">IPs bloquées</div>
                </div>
            </div>
            
            <div class="monitoring-actions">
                <button id="refreshStats" class="btn btn-primary">Rafraîchir</button>
                <button id="exportSIEMLogs" class="btn btn-secondary">Exporter vers SIEM</button>
                <button id="purgeOldLogs" class="btn btn-danger">Purger les anciens logs</button>
            </div>
        </div>
    `;
    
    // Mettre à jour les statistiques
    updateMonitoringStats();
    
    // Ajouter les gestionnaires d'événements
    document.getElementById('refreshStats').addEventListener('click', function() {
        updateMonitoringStats();
    });
    
    document.getElementById('exportSIEMLogs').addEventListener('click', function() {
        if (window.siemIntegration && window.siemIntegration.downloadLogs) {
            window.siemIntegration.downloadLogs(securityMonitoringConfig.siemExport.defaultType);
        } else {
            alert('Module d\'intégration SIEM non disponible');
        }
    });
    
    document.getElementById('purgeOldLogs').addEventListener('click', function() {
        if (confirm('Êtes-vous sûr de vouloir purger les anciens logs ?')) {
            purgeOldLogs();
            updateMonitoringStats();
            alert('Purge des anciens logs effectuée');
        }
    });
}

// Fonction pour mettre à jour les statistiques de surveillance
function updateMonitoringStats() {
    if (!window.securityLogs) return;
    
    const logs = window.securityLogs.getAllLogs();
    const failedLogins = logs.filter(log => log.status === window.securityLogs.LOG_TYPES.FAILURE);
    const activeAlerts = window.securityLogs.getActiveAlerts ? window.securityLogs.getActiveAlerts() : [];
    
    // Compter les IPs bloquées
    let blockedIPsCount = 0;
    const uniqueIPs = [...new Set(logs.map(log => log.ipAddress))];
    
    uniqueIPs.forEach(ip => {
        if (window.securityLogs.isIPBlocked && window.securityLogs.isIPBlocked(ip).blocked) {
            blockedIPsCount++;
        }
    });
    
    // Mettre à jour les compteurs
    document.getElementById('totalLogsCount').textContent = logs.length;
    document.getElementById('failedLoginsCount').textContent = failedLogins.length;
    document.getElementById('activeAlertsCount').textContent = activeAlerts.length;
    document.getElementById('blockedIPsCount').textContent = blockedIPsCount;
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.securityMonitoring = {
    config: securityMonitoringConfig,
    checkLogs: checkSecurityLogs,
    purgeOldLogs: purgeOldLogs,
    exportToSIEM: exportLogsToSIEM,
    updateStats: updateMonitoringStats,
    sendAlert: sendSecurityAlert
};