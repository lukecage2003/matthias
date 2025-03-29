// Module de surveillance de sécurité pour Tech Shield

document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si la configuration de sécurité centralisée est disponible
    if (!window.securityConfig) {
        console.warn('Configuration de sécurité non trouvée, utilisation des paramètres par défaut');
        return;
    }
    
    // Initialiser le moniteur de sécurité
    initSecurityMonitor();
    
    /**
     * Initialise le moniteur de sécurité
     */
    function initSecurityMonitor() {
        // Créer le conteneur pour les notifications de sécurité
        createSecurityNotificationContainer();
        
        // Surveiller les tentatives de connexion
        monitorLoginAttempts();
        
        // Surveiller les accès IP
        monitorIPAccess();
        
        // Vérifier les permissions utilisateur
        checkUserPermissions();
        
        // Afficher les statistiques de sécurité si on est sur la page d'administration
        if (document.querySelector('.admin-container')) {
            displaySecurityStats();
        }
    }
    
    /**
     * Crée un conteneur pour les notifications de sécurité
     */
    function createSecurityNotificationContainer() {
        // Vérifier si le conteneur existe déjà
        if (document.getElementById('security-notifications')) return;
        
        // Créer le conteneur
        const container = document.createElement('div');
        container.id = 'security-notifications';
        container.className = 'security-notifications';
        container.style.position = 'fixed';
        container.style.bottom = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        container.style.maxWidth = '350px';
        container.style.maxHeight = '80vh';
        container.style.overflowY = 'auto';
        container.style.display = 'flex';
        container.style.flexDirection = 'column-reverse';
        container.style.gap = '10px';
        
        // Ajouter le conteneur au body
        document.body.appendChild(container);
    }
    
    /**
     * Affiche une notification de sécurité
     */
    function showSecurityNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('security-notifications');
        if (!container) return;
        
        // Créer la notification
        const notification = document.createElement('div');
        notification.className = `security-notification ${type}`;
        notification.innerHTML = `
            <div class="notification-icon">
                ${type === 'success' ? '✓' : type === 'warning' ? '⚠' : type === 'error' ? '✗' : 'ℹ'}
            </div>
            <div class="notification-content">
                <div class="notification-message">${message}</div>
                <div class="notification-time">${new Date().toLocaleTimeString()}</div>
            </div>
            <div class="notification-close">×</div>
        `;
        
        // Styles pour la notification
        notification.style.backgroundColor = type === 'success' ? '#d4edda' : 
                                           type === 'warning' ? '#fff3cd' : 
                                           type === 'error' ? '#f8d7da' : '#d1ecf1';
        notification.style.color = type === 'success' ? '#155724' : 
                                 type === 'warning' ? '#856404' : 
                                 type === 'error' ? '#721c24' : '#0c5460';
        notification.style.border = `1px solid ${type === 'success' ? '#c3e6cb' : 
                                                type === 'warning' ? '#ffeeba' : 
                                                type === 'error' ? '#f5c6cb' : '#bee5eb'}`;
        notification.style.borderRadius = '4px';
        notification.style.padding = '10px';
        notification.style.marginBottom = '10px';
        notification.style.boxShadow = '0 2px 5px rgba(0,0,0,0.1)';
        notification.style.display = 'flex';
        notification.style.alignItems = 'center';
        notification.style.opacity = '0';
        notification.style.transition = 'opacity 0.3s ease-in-out';
        
        // Ajouter la notification au conteneur
        container.appendChild(notification);
        
        // Afficher la notification avec une animation
        setTimeout(() => {
            notification.style.opacity = '1';
        }, 10);
        
        // Ajouter un gestionnaire pour fermer la notification
        const closeButton = notification.querySelector('.notification-close');
        closeButton.style.cursor = 'pointer';
        closeButton.style.marginLeft = 'auto';
        closeButton.style.fontSize = '20px';
        closeButton.style.fontWeight = 'bold';
        
        closeButton.addEventListener('click', () => {
            notification.style.opacity = '0';
            setTimeout(() => {
                container.removeChild(notification);
            }, 300);
        });
        
        // Fermer automatiquement la notification après la durée spécifiée
        if (duration > 0) {
            setTimeout(() => {
                if (container.contains(notification)) {
                    notification.style.opacity = '0';
                    setTimeout(() => {
                        if (container.contains(notification)) {
                            container.removeChild(notification);
                        }
                    }, 300);
                }
            }, duration);
        }
        
        return notification;
    }
    
    /**
     * Surveille les tentatives de connexion
     */
    function monitorLoginAttempts() {
        // Vérifier si le module de journalisation est disponible
        if (!window.securityLogs) return;
        
        // S'abonner aux événements de connexion
        window.securityLogs.subscribeToLoginEvents(function(log) {
            // Déterminer le type de notification en fonction du statut du log
            let notificationType = 'info';
            let message = '';
            
            switch(log.status) {
                case window.securityLogs.LOG_TYPES.SUCCESS:
                    notificationType = 'success';
                    message = `Connexion réussie pour ${log.email}`;
                    break;
                case window.securityLogs.LOG_TYPES.FAILURE:
                    notificationType = 'error';
                    message = `Échec de connexion pour ${log.email || 'un utilisateur'}`;
                    break;
                case window.securityLogs.LOG_TYPES.SUSPICIOUS:
                    notificationType = 'warning';
                    message = `Activité suspecte détectée: ${log.details}`;
                    break;
                case window.securityLogs.LOG_TYPES.WARNING:
                    notificationType = 'warning';
                    message = log.details;
                    break;
                default:
                    message = log.details;
            }
            
            // Afficher une notification pour les événements importants
            if (log.status !== window.securityLogs.LOG_TYPES.INFO) {
                showSecurityNotification(message, notificationType);
            }
            
            // Si on est sur la page d'administration, mettre à jour les statistiques
            if (document.querySelector('.admin-container')) {
                updateSecurityStats();
            }
        });
    }
    
    /**
     * Surveille les accès IP
     */
    function monitorIPAccess() {
        // Vérifier si le module de liste blanche d'IP est disponible
        if (!window.ipWhitelist) return;
        
        // Vérifier l'accès IP actuel
        const ipAccess = window.ipWhitelist.checkIPAccess();
        
        // Si l'accès est refusé et que nous sommes sur une page d'administration
        if (!ipAccess.allowed && window.location.pathname.includes('admin')) {
            // Rediriger vers la page d'accès non autorisé
            window.location.href = 'unauthorized.html';
        }
        
        // Si l'accès est autorisé mais avec un avertissement
        if (ipAccess.allowed && ipAccess.warning) {
            showSecurityNotification(ipAccess.warning, 'warning', 10000);
        }
    }
    
    /**
     * Vérifie les permissions de l'utilisateur pour la page actuelle
     */
    function checkUserPermissions() {
        // Vérifier si le module de permissions est disponible
        if (!window.userPermissions) return;
        
        // Obtenir le nom de la page actuelle
        const pageName = window.location.pathname.split('/').pop();
        
        // Obtenir le rôle de l'utilisateur
        const userRole = sessionStorage.getItem('userRole') || 'guest';
        
        // Vérifier si l'utilisateur a accès à la page
        if (window.checkPagePermission && !window.checkPagePermission(pageName, userRole)) {
            // Rediriger vers la page d'accès non autorisé
            window.location.href = 'unauthorized.html';
        }
    }
    
    /**
     * Affiche les statistiques de sécurité sur la page d'administration
     */
    function displaySecurityStats() {
        // Vérifier si le conteneur de statistiques existe
        const statsContainer = document.querySelector('.security-stats');
        if (!statsContainer) return;
        
        // Mettre à jour les statistiques
        updateSecurityStats();
        
        // Mettre à jour les statistiques toutes les 30 secondes
        setInterval(updateSecurityStats, 30000);
    }
    
    /**
     * Met à jour les statistiques de sécurité
     */
    function updateSecurityStats() {
        // Vérifier si le conteneur de statistiques existe
        const statsContainer = document.querySelector('.security-stats');
        if (!statsContainer || !window.securityLogs) return;
        
        // Obtenir tous les logs
        const logs = window.securityLogs.getAllLogs();
        
        // Calculer les statistiques
        const stats = {
            totalLogins: logs.filter(log => log.status === window.securityLogs.LOG_TYPES.SUCCESS).length,
            failedLogins: logs.filter(log => log.status === window.securityLogs.LOG_TYPES.FAILURE).length,
            suspiciousActivities: logs.filter(log => log.status === window.securityLogs.LOG_TYPES.SUSPICIOUS).length,
            lastActivity: logs.length > 0 ? new Date(logs[0].timestamp) : null
        };
        
        // Mettre à jour l'interface
        statsContainer.innerHTML = `
            <div class="stat-item">
                <div class="stat-value">${stats.totalLogins}</div>
                <div class="stat-label">Connexions réussies</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${stats.failedLogins}</div>
                <div class="stat-label">Tentatives échouées</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${stats.suspiciousActivities}</div>
                <div class="stat-label">Activités suspectes</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${stats.lastActivity ? stats.lastActivity.toLocaleTimeString() : 'N/A'}</div>
                <div class="stat-label">Dernière activité</div>
            </div>
        `;
    }
});