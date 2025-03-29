// Système d'alerte de sécurité avancé pour Tech Shield

// Configuration du système d'alerte
const securityAlertSystemConfig = {
    // Seuils de détection
    thresholds: {
        // Nombre de tentatives de connexion échouées avant de déclencher une alerte
        failedLoginAttempts: 5,
        
        // Fenêtre de temps pour les tentatives échouées (en minutes)
        timeWindowMinutes: 15,
        
        // Durée de blocage automatique après détection (en minutes)
        autoBlockDuration: 30,
        
        // Seuil pour les attaques par force brute (tentatives par minute)
        bruteForceThreshold: 10,
        
        // Seuil pour les tentatives depuis plusieurs pays
        multiCountryAttempts: 3
    },
    
    // Configuration des notifications
    notifications: {
        // Activer les notifications dans l'interface
        enableUI: true,
        
        // Activer les notifications par email (simulation)
        enableEmail: true,
        
        // Adresses email des administrateurs (dans un environnement réel)
        adminEmails: ['admin@techshield.com'],
        
        // Durée d'affichage des notifications (en secondes)
        displayDuration: 10
    },
    
    // Configuration des actions automatiques
    autoActions: {
        // Bloquer automatiquement les IP suspectes
        blockSuspiciousIPs: true,
        
        // Verrouiller temporairement les comptes après trop de tentatives échouées
        lockAccounts: true,
        
        // Durée de verrouillage des comptes (en minutes)
        accountLockDuration: 30,
        
        // Exiger une vérification supplémentaire après détection d'activité suspecte
        requireAdditionalVerification: true
    },
    
    // Configuration de l'intégration SIEM
    siemIntegration: {
        // Activer l'envoi automatique des alertes au SIEM
        enabled: true,
        
        // Niveau de gravité minimum pour l'envoi au SIEM
        minSeverityLevel: 'medium',
        
        // Inclure les données contextuelles
        includeContextData: true
    }
};

// Stockage des alertes actives
const activeAlerts = [];

// Stockage des comptes verrouillés
const lockedAccounts = {};

// Stockage des statistiques d'alerte
const alertStats = {
    totalAlerts: 0,
    byType: {},
    bySeverity: {},
    byIP: {},
    byUser: {}
};

// Fonction pour initialiser le système d'alerte
function initAlertSystem() {
    console.log('Initialisation du système d\'alerte de sécurité...');
    
    // Vérifier si le module de logs de sécurité est disponible
    if (!window.securityLogs) {
        console.error('Le module de journalisation de sécurité n\'est pas disponible');
        return false;
    }
    
    // S'abonner aux événements de connexion
    const loginEventIndex = window.securityLogs.subscribeToLoginEvents(handleLoginEvent);
    
    // Créer le conteneur de notifications si nécessaire
    if (securityAlertSystemConfig.notifications.enableUI) {
        createNotificationContainer();
    }
    
    // Charger les alertes depuis le localStorage
    loadAlertsFromStorage();
    
    return true;
}

// Fonction pour gérer les événements de connexion
function handleLoginEvent(log) {
    // Vérifier si c'est une tentative échouée
    if (log.status === window.securityLogs.LOG_TYPES.FAILURE) {
        checkFailedLoginThreshold(log);
    }
    
    // Vérifier si c'est une connexion réussie pour détecter les connexions suspectes
    if (log.status === window.securityLogs.LOG_TYPES.SUCCESS) {
        checkSuspiciousLogin(log);
    }
    
    // Vérifier les autres types d'activités suspectes
    if (window.advancedSecurityLogs) {
        const suspiciousActivities = window.advancedSecurityLogs.detectSuspiciousActivity(log.email);
        if (suspiciousActivities.length > 0) {
            handleSuspiciousActivities(log.email, log.ipAddress, suspiciousActivities);
        }
    }
}

// Fonction pour vérifier si le seuil de tentatives échouées est atteint
function checkFailedLoginThreshold(log) {
    // Obtenir les logs récents pour cette adresse IP
    const ipLogs = window.securityLogs.getLogsByIP(log.ipAddress);
    const timeWindowAgo = new Date(Date.now() - securityAlertSystemConfig.thresholds.timeWindowMinutes * 60 * 1000);
    
    // Filtrer les tentatives échouées récentes
    const recentFailedLogs = ipLogs.filter(l => 
        l.status === window.securityLogs.LOG_TYPES.FAILURE && 
        new Date(l.timestamp) >= timeWindowAgo
    );
    
    // Si le seuil est atteint, créer une alerte
    if (recentFailedLogs.length >= securityAlertSystemConfig.thresholds.failedLoginAttempts) {
        createAlert({
            type: 'failed_login_threshold',
            severity: 'high',
            ipAddress: log.ipAddress,
            email: log.email,
            details: `${recentFailedLogs.length} tentatives de connexion échouées détectées dans les dernières ${securityAlertSystemConfig.thresholds.timeWindowMinutes} minutes`,
            timestamp: new Date().toISOString(),
            relatedLogs: recentFailedLogs
        });
        
        // Exécuter les actions automatiques configurées
        if (securityAlertSystemConfig.autoActions.blockSuspiciousIPs) {
            blockIP(log.ipAddress);
        }
        
        if (securityAlertSystemConfig.autoActions.lockAccounts && log.email) {
            lockAccount(log.email);
        }
    }
    
    // Vérifier s'il y a une attaque par force brute
    checkBruteForceAttack(log.ipAddress);
}

// Fonction pour vérifier s'il y a une attaque par force brute
function checkBruteForceAttack(ipAddress) {
    // Obtenir tous les logs
    const logs = window.securityLogs.getAllLogs();
    const oneMinuteAgo = new Date(Date.now() - 60 * 1000);
    
    // Compter les tentatives de connexion depuis cette IP dans la dernière minute
    const recentAttempts = logs.filter(log => 
        log.ipAddress === ipAddress && 
        log.status === window.securityLogs.LOG_TYPES.FAILURE &&
        new Date(log.timestamp) >= oneMinuteAgo
    );
    
    // Si le seuil est atteint, créer une alerte
    if (recentAttempts.length >= securityAlertSystemConfig.thresholds.bruteForceThreshold) {
        createAlert({
            type: 'brute_force_attack',
            severity: 'critical',
            ipAddress: ipAddress,
            details: `Attaque par force brute détectée: ${recentAttempts.length} tentatives en 1 minute`,
            timestamp: new Date().toISOString(),
            relatedLogs: recentAttempts
        });
        
        // Bloquer l'IP pour une durée plus longue
        if (securityAlertSystemConfig.autoActions.blockSuspiciousIPs) {
            blockIP(ipAddress, 120); // 2 heures
        }
    }
}

// Fonction pour vérifier si une connexion est suspecte
function checkSuspiciousLogin(log) {
    // Vérifier si l'utilisateur existe
    if (!log.email) return;
    
    // Obtenir tous les logs de l'utilisateur
    const userLogs = window.securityLogs.getLogsByUser(log.email);
    
    // Obtenir les connexions réussies précédentes
    const previousSuccessfulLogins = userLogs.filter(l => 
        l.status === window.securityLogs.LOG_TYPES.SUCCESS && 
        l.timestamp !== log.timestamp
    );
    
    // Si c'est la première connexion, ne pas déclencher d'alerte
    if (previousSuccessfulLogins.length === 0) return;
    
    // Vérifier si l'adresse IP est connue
    const knownIPs = new Set();
    previousSuccessfulLogins.forEach(l => knownIPs.add(l.ipAddress));
    
    // Si l'IP est inconnue, créer une alerte
    if (!knownIPs.has(log.ipAddress)) {
        createAlert({
            type: 'suspicious_ip_login',
            severity: 'high',
            ipAddress: log.ipAddress,
            email: log.email,
            details: `Connexion depuis une adresse IP inconnue: ${log.ipAddress}`,
            timestamp: new Date().toISOString(),
            location: log.location || 'Inconnue',
            userAgent: log.userAgent || 'Inconnu'
        });
        
        // Si la vérification supplémentaire est activée, l'exiger
        if (securityAlertSystemConfig.autoActions.requireAdditionalVerification) {
            requireAdditionalVerification(log.email);
        }
    }
}

// Fonction pour gérer les activités suspectes
function handleSuspiciousActivities(email, ipAddress, activities) {
    // Créer une alerte pour chaque activité suspecte
    activities.forEach(activity => {
        createAlert({
            type: 'suspicious_activity',
            severity: activity.severity,
            ipAddress: ipAddress,
            email: email,
            details: `${activity.description}: ${activity.details}`,
            timestamp: new Date().toISOString()
        });
    });
    
    // Si au moins une activité est de gravité élevée ou critique, exécuter des actions automatiques
    const hasCritical = activities.some(activity => 
        activity.severity === 'high' || activity.severity === 'critical'
    );
    
    if (hasCritical) {
        if (securityAlertSystemConfig.autoActions.requireAdditionalVerification && email) {
            requireAdditionalVerification(email);
        }
    }
}

// Fonction pour créer une alerte
function createAlert(alertData) {
    // Générer un ID unique pour l'alerte
    const alertId = 'alert-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
    
    // Créer l'objet d'alerte
    const alert = {
        id: alertId,
        ...alertData,
        status: 'active',
        createdAt: new Date().toISOString(),
        actions: []
    };
    
    // Ajouter l'alerte à la liste des alertes actives
    activeAlerts.push(alert);
    
    // Mettre à jour les statistiques
    updateAlertStats(alert);
    
    // Sauvegarder les alertes dans le localStorage
    saveAlertsToStorage();
    
    // Enregistrer l'alerte dans les logs
    if (window.securityLogs) {
        window.securityLogs.addLoginLog(
            alert.email || 'système', 
            alert.ipAddress || 'N/A', 
            window.securityLogs.LOG_TYPES.SUSPICIOUS, 
            `ALERTE: ${alert.details}`
        );
    }
    
    // Afficher une notification
    if (securityAlertSystemConfig.notifications.enableUI) {
        showAlertNotification(alert);
    }
    
    // Envoyer l'alerte par email (simulation)
    if (securityAlertSystemConfig.notifications.enableEmail) {
        sendAlertEmail(alert);
    }
    
    // Envoyer l'alerte au SIEM si l'intégration est activée
    if (securityAlertSystemConfig.siemIntegration.enabled && 
        isSeverityAboveThreshold(alert.severity, securityAlertSystemConfig.siemIntegration.minSeverityLevel)) {
        sendAlertToSIEM(alert);
    }
    
    return alert;
}

// Fonction pour mettre à jour les statistiques d'alerte
function updateAlertStats(alert) {
    // Incrémenter le compteur total
    alertStats.totalAlerts++;
    
    // Mettre à jour les statistiques par type
    if (!alertStats.byType[alert.type]) {
        alertStats.byType[alert.type] = 0;
    }
    alertStats.byType[alert.type]++;
    
    // Mettre à jour les statistiques par gravité
    if (!alertStats.bySeverity[alert.severity]) {
        alertStats.bySeverity[alert.severity] = 0;
    }
    alertStats.bySeverity[alert.severity]++;
    
    // Mettre à jour les statistiques par IP
    if (alert.ipAddress) {
        if (!alertStats.byIP[alert.ipAddress]) {
            alertStats.byIP[alert.ipAddress] = 0;
        }
        alertStats.byIP[alert.ipAddress]++;
    }
    
    // Mettre à jour les statistiques par utilisateur
    if (alert.email) {
        if (!alertStats.byUser[alert.email]) {
            alertStats.byUser[alert.email] = 0;
        }
        alertStats.byUser[alert.email]++;
    }
}

// Fonction pour vérifier si une gravité est supérieure ou égale à un seuil
function isSeverityAboveThreshold(severity, threshold) {
    const severityLevels = {
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    };
    
    return severityLevels[severity] >= severityLevels[threshold];
}

// Fonction pour bloquer une adresse IP
function blockIP(ipAddress, durationMinutes = securityAlertSystemConfig.autoActions.autoBlockDuration) {
    if (window.securityLogs && window.securityLogs.blockIP) {
        window.securityLogs.blockIP(ipAddress, durationMinutes);
        
        // Ajouter l'action à toutes les alertes concernant cette IP
        activeAlerts.forEach(alert => {
            if (alert.ipAddress === ipAddress) {
                alert.actions.push({
                    type: 'block_ip',
                    timestamp: new Date().toISOString(),
                    details: `IP bloquée pour ${durationMinutes} minutes`
                });
            }
        });
        
        // Sauvegarder les alertes mises à jour
        saveAlertsToStorage();
        
        return true;
    }
    
    return false;
}

// Fonction pour verrouiller un compte
function lockAccount(email, durationMinutes = securityAlertSystemConfig.autoActions.accountLockDuration) {
    const expirationTime = new Date();
    expirationTime.setMinutes(expirationTime.getMinutes() + durationMinutes);
    
    lockedAccounts[email] = expirationTime.toISOString();
    
    // Ajouter l'action à toutes les alertes concernant cet utilisateur
    activeAlerts.forEach(alert => {
        if (alert.email === email) {
            alert.actions.push({
                type: 'lock_account',
                timestamp: new Date().toISOString(),
                details: `Compte verrouillé pour ${durationMinutes} minutes`
            });
        }
    });
    
    // Sauvegarder les alertes mises à jour
    saveAlertsToStorage();
    
    // Enregistrer le verrouillage dans les logs
    if (window.securityLogs) {
        window.securityLogs.addLoginLog(
            email, 
            'N/A', 
            window.securityLogs.LOG_TYPES.WARNING, 
            `Compte verrouillé temporairement pour ${durationMinutes} minutes suite à trop de tentatives échouées`
        );
    }
    
    return true;
}

// Fonction pour vérifier si un compte est verrouillé
function isAccountLocked(email) {
    if (lockedAccounts[email]) {
        const now = new Date();
        const lockExpiration = new Date(lockedAccounts[email]);
        
        if (now < lockExpiration) {
            // Calculer le temps restant en minutes
            const remainingMs = lockExpiration - now;
            const remainingMinutes = Math.ceil(remainingMs / (60 * 1000));
            
            return { 
                locked: true, 
                expiresAt: lockedAccounts[email],
                remainingMinutes: remainingMinutes
            };
        } else {
            // Le verrouillage a expiré, supprimer l'entrée
            delete lockedAccounts[email];
        }
    }
    
    return { locked: false };
}

// Fonction pour exiger une vérification supplémentaire
function requireAdditionalVerification(email) {
    // Dans un environnement réel, cette fonction marquerait le compte comme nécessitant
    // une vérification supplémentaire (2FA, question de sécurité, etc.)
    console.log(`Vérification supplémentaire requise pour ${email}`);
    
    // Ajouter l'action à toutes les alertes concernant cet utilisateur
    activeAlerts.forEach(alert => {
        if (alert.email === email) {
            alert.actions.push({
                type: 'require_verification',
                timestamp: new Date().toISOString(),
                details: 'Vérification supplémentaire requise pour la prochaine connexion'
            });
        }
    });
    
    // Sauvegarder les alertes mises à jour
    saveAlertsToStorage();
    
    // Enregistrer l'action dans les logs
    if (window.securityLogs) {
        window.securityLogs.addLoginLog(
            email, 
            'N/A', 
            window.securityLogs.LOG_TYPES.WARNING, 
            'Vérification supplémentaire requise pour la prochaine connexion'
        );
    }
    
    return true;
}

// Fonction pour résoudre une alerte
function resolveAlert(alertId, resolution = 'Résolue manuellement') {
    const alertIndex = activeAlerts.findIndex(alert => alert.id === alertId);
    
    if (alertIndex !== -1) {
        const alert = activeAlerts[alertIndex];
        alert.status = 'resolved';
        alert.resolvedAt = new Date().toISOString();
        alert.resolution = resolution;
        
        // Enregistrer la résolution dans les logs
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système', 
                alert.ipAddress || 'N/A', 
                window.securityLogs.LOG_TYPES.INFO, 
                `Alerte résolue: ${alert.details} - ${resolution}`
            );
        }
        
        // Supprimer l'alerte de la liste des alertes actives
        activeAlerts.splice(alertIndex, 1);
        
        // Sauvegarder les alertes mises à jour
        saveAlertsToStorage();
        
        return true;
    }
    
    return false;
}

// Fonction pour créer le conteneur de notifications
function createNotificationContainer() {
    // Vérifier si le conteneur existe déjà
    let container = document.querySelector('.security-notifications-container');
    
    if (!container) {
        // Créer le conteneur
        container = document.createElement('div');
        container.className = 'security-notifications-container';
        document.body.appendChild(container);
        
        // Ajouter les styles CSS
        const style = document.createElement('style');
        style.textContent = `
            .security-notifications-container {
                position: fixed;
                top: 20px;
                right: 20px;
                width: 350px;
                max-height: 80vh;
                overflow-y: auto;
                z-index: 9999;
                display: flex;
                flex-direction: column;
                gap: 10px;
            }
            
            .security-notification {
                background-color: #fff;
                border-radius: 5px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                padding: 15px;
                margin-bottom: 10px;
                animation: slideIn 0.3s ease-out;
                border-left: 5px solid #ccc;
            }
            
            .security-notification.low {
                border-left-color: #4caf50;
            }
            
            .security-notification.medium {
                border-left-color: #ff9800;
            }
            
            .security-notification.high {
                border-left-color: #f44336;
            }
            
            .security-notification.critical {
                border-left-color: #9c27b0;
                background-color: #fce4ec;
            }
            
            .notification-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }
            
            .notification-title {
                font-weight: bold;
                font-size: 16px;
            }
            
            .notification-time {
                font-size: 12px;
                color: #666;
            }
            
            .notification-content {
                margin-bottom: 10px;
            }
            
            .notification-actions {
                display: flex;
                justify-content: flex-end;
                gap: 10px;
            }
            
            .notification-actions button {
                padding: 5px 10px;
                border: none;
                border-radius: 3px;
                cursor: pointer;
                font-size: 12px;
            }
            
            .view-details-btn {
                background-color: #2196f3;
                color: white;
            }
            
            .dismiss-btn {
                background-color: #e0e0e0;
                color: #333;
            }
            
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            
            @keyframes fadeOut {
                from { opacity: 1; }
                to { opacity: 0; }
            }
            
            .security-notification.fade-out {
                animation: fadeOut 0.5s ease-out forwards;
            }
        `;
        document.head.appendChild(style);
    }
    
    return container;
}

// Fonction pour afficher une notification d'alerte
function showAlertNotification(alert) {
    const container = document.querySelector('.security-notifications-container');
    if (!container) return;
    
    // Créer l'élément de notification
    const notification = document.createElement('div');
    notification.className = `security-notification ${alert.severity}`;
    notification.dataset.alertId = alert.id;
    
    // Construire le contenu de la notification
    notification.innerHTML = `
        <div class="notification-header">
            <span class="notification-title">Alerte de sécurité (${alert.severity})</span>
            <span class="notification-time">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="notification-content">
            <p>${alert.details}</p>
            ${alert.email ? `<p>Utilisateur: ${alert.email}</p>` : ''}
            ${alert.ipAddress ? `<p>IP: ${alert.ipAddress}</p>` : ''}
        </div>
        <div class="notification-actions">
            <button class="view-details-btn">Voir les détails</button>
            <button class="dismiss-btn">Ignorer</button>
        </div>
    `;
    
    // Ajouter la notification au conteneur
    container.insertBefore(notification, container.firstChild);
    
    // Ajouter des gestionnaires d'événements pour les boutons
    const viewDetailsBtn = notification.querySelector('.view-details-btn');
    const dismissBtn = notification.querySelector('.dismiss-btn');
    
    if (viewDetailsBtn) {
        viewDetailsBtn.addEventListener('click', function() {
            // Rediriger vers la page des logs ou afficher un modal avec les détails
            const tabLinks = document.querySelectorAll('.admin-nav a');
            tabLinks.forEach(link => {
                if (link.getAttribute('data-tab') === 'logs') {
                    link.click();
                }
            });
        });
    }
    
    if (dismissBtn) {
        dismissBtn.addEventListener('click', function() {
            // Supprimer la notification
            notification.classList.add('fade-out');
            setTimeout(() => {
                notification.remove();
            }, 500);
        });
    }
    
    // Supprimer la notification après un délai
    if (securityAlertSystemConfig.notifications.displayDuration > 0) {
        setTimeout(() => {
            if (notification.parentNode) {
                notification.classList.add('fade-out');
                setTimeout(() => {
                    notification.remove();
                }, 500);
            }
        }, securityAlertSystemConfig.notifications.displayDuration * 1000);
    }
}

// Fonction pour envoyer une alerte par email (simulation)
function sendAlertEmail(alert) {
    // Dans un environnement réel, cette fonction enverrait un email
    // Pour cette démonstration, nous simulons l'envoi
    console.log(`Simulation d'envoi d'email d'alerte:`, {
        to: securityAlertSystemConfig.notifications.adminEmails,
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
}

// Fonction pour envoyer une alerte au SIEM
function sendAlertToSIEM(alert) {
    // Vérifier si le module d'intégration SIEM est disponible
    if (window.siemIntegration && window.siemIntegration.sendLogs) {
        // Préparer les données contextuelles si nécessaire
        let contextData = {};
        
        if (securityAlertSystemConfig.siemIntegration.includeContextData) {
            contextData = {
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                screenResolution: `${window.screen.width}x${window.screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                relatedLogs: alert.relatedLogs || []
            };
        }
        
        // Créer un log enrichi pour le SIEM
        const siemLog = {
            timestamp: alert.timestamp,
            email: alert.email || 'unknown',
            ipAddress: alert.ipAddress || 'N/A',
            status: 'ALERT',
            details: `[${alert.severity.toUpperCase()}] ${alert.details}`,
            alertType: alert.type,
            alertId: alert.id,
            severity: alert.severity,
            contextData: contextData
        };
        
        // Envoyer le log au SIEM
        window.siemIntegration.sendLogs();
        
        return true;
    }
    
    return false;
}

// Fonction pour sauvegarder les alertes dans le localStorage
function saveAlertsToStorage() {
    if (typeof localStorage !== 'undefined') {
        localStorage.setItem('securityAlerts', JSON.stringify(activeAlerts));
    }
}

// Fonction pour charger les alertes depuis le localStorage
function loadAlertsFromStorage() {
    if (typeof localStorage !== 'undefined') {
        const storedAlerts = localStorage.getItem('securityAlerts');
        if (storedAlerts) {
            // Fusionner avec les alertes actuelles
            const parsedAlerts = JSON.parse(storedAlerts);
            
            // Vider le tableau actuel et ajouter les alertes stockées
            activeAlerts.length = 0;
            parsedAlerts.forEach(alert => activeAlerts.push(alert));
        }
    }
}

// Fonction pour obtenir toutes les alertes actives
function getActiveAlerts() {
    return activeAlerts;
}

// Fonction pour obtenir les statistiques d'alerte
function getAlertStats() {
    return alertStats;
}

// Fonction pour initialiser l'interface utilisateur du système d'alerte
function initAlertSystemUI() {
    const alertSystemContainer = document.getElementById('alertSystem');
    if (!alertSystemContainer) return;
    
    // Créer l'interface utilisateur
    alertSystemContainer.innerHTML = `
        <div class="alert-system-panel">
            <h3>Système d'alerte</h3>
            
            <div class="alert-stats">
                <div class="stat-card">
                    <div class="stat-value">${alertStats.totalAlerts}</div>
                    <div class="stat-label">Alertes totales</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">${activeAlerts.length}</div>
                    <div class="stat-label">Alertes actives</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">${alertStats.bySeverity.critical || 0}</div>
                    <div class="stat-label">Alertes critiques</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">${alertStats.bySeverity