// Module d'interface pour le tableau de bord de sécurité de Tech Shield

document.addEventListener("DOMContentLoaded", function() {
    // Vérifier si nous sommes sur la page d'administration
    if (!document.querySelector('.admin-container')) return;
    
    // Vérifier si les modules de sécurité sont disponibles
    const securityModulesAvailable = {
        ipWhitelist: !!window.ipWhitelist,
        securityLogs: !!window.securityLogs,
        userPermissions: !!window.userPermissions,
        advancedSecurityLogs: !!window.advancedSecurityLogs,
        loginSecurity: !!window.loginSecurity,
        twoFA: !!window.twoFA
    };
    
    // Initialiser les composants du tableau de bord de sécurité
    initSecurityDashboard();
    
    /**
     * Initialise le tableau de bord de sécurité
     */
    function initSecurityDashboard() {
        // Initialiser la gestion de la liste blanche d'IP
        if (securityModulesAvailable.ipWhitelist) {
            initIPWhitelistManager();
        }
        
        // Initialiser la détection des activités suspectes
        if (securityModulesAvailable.advancedSecurityLogs) {
            initSuspiciousActivityDetection();
        }
        
        // Initialiser la gestion des permissions utilisateurs
        if (securityModulesAvailable.userPermissions) {
            initUserPermissionsManager();
        }
        
        // Initialiser les statistiques de sécurité
        initSecurityStats();
        
        // Ajouter les gestionnaires d'événements pour les actions de sécurité
        addSecurityEventListeners();
    }
    
    /**
     * Initialise la gestion de la liste blanche d'IP
     */
    function initIPWhitelistManager() {
        const ipListContainer = document.querySelector('.ip-list');
        const addIPForm = document.getElementById('addIPForm');
        
        if (!ipListContainer || !window.ipWhitelist) return;
        
        // Charger la liste des IP autorisées
        const whitelistedIPs = window.ipWhitelist.getAllWhitelistedIPs();
        
        // Vider le conteneur
        ipListContainer.innerHTML = '';
        
        // Afficher les IP autorisées
        if (whitelistedIPs.length === 0) {
            ipListContainer.innerHTML = '<p class="no-data">Aucune adresse IP dans la liste blanche</p>';
        } else {
            whitelistedIPs.forEach(entry => {
                const ipItem = document.createElement('div');
                ipItem.className = 'ip-item';
                
                // Formater la date d'expiration
                let expiryInfo = '';
                if (entry.permanent) {
                    expiryInfo = '<span class="permanent-badge">Permanent</span>';
                } else if (entry.expiresAt) {
                    const expiryDate = new Date(entry.expiresAt);
                    expiryInfo = `<span class="expiry-date">Expire le ${expiryDate.toLocaleDateString()}</span>`;
                }
                
                ipItem.innerHTML = `
                    <div class="ip-info">
                        <span class="ip-address">${entry.ip}</span>
                        <span class="ip-description">${entry.description}</span>
                        ${expiryInfo}
                    </div>
                    <div class="ip-actions">
                        <button class="remove-ip" data-ip="${entry.ip}">Supprimer</button>
                    </div>
                `;
                
                ipListContainer.appendChild(ipItem);
            });
            
            // Ajouter les gestionnaires d'événements pour les boutons de suppression
            document.querySelectorAll('.remove-ip').forEach(button => {
                button.addEventListener('click', function() {
                    const ipAddress = this.getAttribute('data-ip');
                    removeIPFromWhitelist(ipAddress);
                });
            });
        }
        
        // Gestionnaire pour le formulaire d'ajout d'IP
        if (addIPForm) {
            addIPForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const ipInput = document.getElementById('ipAddress');
                const descriptionInput = document.getElementById('ipDescription');
                const permanentCheckbox = document.getElementById('permanentIP');
                
                if (ipInput && descriptionInput) {
                    const ipAddress = ipInput.value.trim();
                    const description = descriptionInput.value.trim();
                    const permanent = permanentCheckbox ? permanentCheckbox.checked : false;
                    
                    // Valider l'adresse IP
                    if (!validateIPAddress(ipAddress)) {
                        showNotification('Adresse IP invalide', 'error');
                        return;
                    }
                    
                    // Ajouter l'IP à la liste blanche
                    const result = window.ipWhitelist.addToWhitelist(ipAddress, description, sessionStorage.getItem('userEmail') || 'admin', permanent);
                    
                    if (result.success) {
                        showNotification('Adresse IP ajoutée à la liste blanche', 'success');
                        initIPWhitelistManager(); // Rafraîchir la liste
                        ipInput.value = '';
                        descriptionInput.value = '';
                        if (permanentCheckbox) permanentCheckbox.checked = false;
                    } else {
                        showNotification(result.reason || 'Erreur lors de l\'ajout de l\'adresse IP', 'error');
                    }
                }
            });
        }
        
        // Afficher le mode actuel (strict ou normal)
        const ipWhitelistMode = document.getElementById('ipWhitelistMode');
        if (ipWhitelistMode) {
            const config = window.ipWhitelist.getConfig();
            ipWhitelistMode.textContent = config.strictMode ? 'Mode strict' : 'Mode normal';
            ipWhitelistMode.className = config.strictMode ? 'mode-strict' : 'mode-normal';
        }
    }
    
    /**
     * Supprime une adresse IP de la liste blanche
     */
    function removeIPFromWhitelist(ipAddress) {
        if (!window.ipWhitelist) return;
        
        // Demander confirmation
        if (confirm(`Êtes-vous sûr de vouloir supprimer l'adresse IP ${ipAddress} de la liste blanche ?`)) {
            const result = window.ipWhitelist.removeFromWhitelist(ipAddress);
            
            if (result) {
                showNotification('Adresse IP supprimée de la liste blanche', 'success');
                initIPWhitelistManager(); // Rafraîchir la liste
            } else {
                showNotification('Erreur lors de la suppression de l\'adresse IP', 'error');
            }
        }
    }
    
    /**
     * Valide une adresse IP
     */
    function validateIPAddress(ipAddress) {
        const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ipAddress);
    }
    
    /**
     * Initialise la détection des activités suspectes
     */
    function initSuspiciousActivityDetection() {
        if (!window.advancedSecurityLogs) return;
        
        const userEmail = sessionStorage.getItem('userEmail');
        if (!userEmail) return;
        
        // Détecter les activités suspectes
        const suspiciousActivities = window.advancedSecurityLogs.detectSuspiciousActivity(userEmail);
        
        // Notifier l'administrateur si des activités suspectes sont détectées
        if (suspiciousActivities.length > 0) {
            window.advancedSecurityLogs.notifyAdmin(suspiciousActivities);
        }
        
        // Générer un rapport de sécurité
        const securityReport = window.advancedSecurityLogs.generateSecurityReport(userEmail);
        
        // Afficher le rapport dans l'interface
        const securityReportContainer = document.getElementById('securityReport');
        if (securityReportContainer && securityReport) {
            // Afficher le niveau de risque
            const riskLevelElement = document.createElement('div');
            riskLevelElement.className = `risk-level risk-${securityReport.riskLevel.toLowerCase()}`;
            riskLevelElement.innerHTML = `
                <h3>Niveau de risque</h3>
                <div class="risk-indicator">${securityReport.riskLevel}</div>
            `;
            securityReportContainer.appendChild(riskLevelElement);
            
            // Afficher les statistiques
            const statsElement = document.createElement('div');
            statsElement.className = 'security-stats';
            statsElement.innerHTML = `
                <h3>Statistiques de connexion</h3>
                <ul>
                    <li>Connexions totales: ${securityReport.statistics.totalLogins}</li>
                    <li>Connexions réussies: ${securityReport.statistics.successfulLogins}</li>
                    <li>Connexions échouées: ${securityReport.statistics.failedLogins}</li>
                    <li>Taux de réussite: ${securityReport.statistics.successRate}</li>
                </ul>
            `;
            securityReportContainer.appendChild(statsElement);
            
            // Afficher les activités suspectes
            if (suspiciousActivities.length > 0) {
                const activitiesElement = document.createElement('div');
                activitiesElement.className = 'suspicious-activities';
                activitiesElement.innerHTML = `
                    <h3>Activités suspectes détectées</h3>
                    <ul>
                        ${suspiciousActivities.map(activity => `
                            <li>
                                <strong>${activity.description}</strong>: ${activity.details}
                                <span class="severity-badge ${activity.severity}">${activity.severity}</span>
                            </li>
                        `).join('')}
                    </ul>
                `;
                securityReportContainer.appendChild(activitiesElement);
            }
        }
    }
    
    /**
     * Initialise la gestion des permissions utilisateurs
     */
    function initUserPermissionsManager() {
        if (!window.userPermissions) return;
        
        const userRole = sessionStorage.getItem('userRole') || 'guest';
        const userPermissionsContainer = document.getElementById('userPermissions');
        
        if (userPermissionsContainer) {
            // Obtenir les permissions de l'utilisateur
            const permissions = window.userPermissions.getUserPermissions(userRole);
            const permissionDescriptions = window.userPermissions.getAllPermissionDescriptions();
            
            // Afficher les permissions
            userPermissionsContainer.innerHTML = `
                <h3>Vos permissions (${userRole})</h3>
                <ul class="permissions-list">
                    ${permissions.map(permission => `
                        <li>
                            <span class="permission-name">${permission}</span>
                            <span class="permission-description">${permissionDescriptions[permission] || permission}</span>
                        </li>
                    `).join('')}
                </ul>
            `;
        }
        
        // Si l'utilisateur est administrateur, afficher la gestion des rôles
        if (userRole === 'admin') {
            const rolesContainer = document.getElementById('userRoles');
            if (rolesContainer) {
                const availableRoles = window.userPermissions.getAvailableRoles();
                
                rolesContainer.innerHTML = `
                    <h3>Gestion des rôles</h3>
                    <div class="roles-list">
                        ${Object.keys(availableRoles).map(role => `
                            <div class="role-item">
                                <div class="role-info">
                                    <span class="role-name">${availableRoles[role].name}</span>
                                    <span class="permission-count">${availableRoles[role].permissionCount} permissions</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                `;
            }
        }
    }
    
    /**
     * Initialise les statistiques de sécurité
     */
    function initSecurityStats() {
        const securityStatsContainer = document.getElementById('securityStats');
        if (!securityStatsContainer) return;
        
        // Statistiques de base
        let totalLogs = 0;
        let failedLogins = 0;
        let suspiciousActivities = 0;
        
        // Obtenir les statistiques depuis les modules disponibles
        if (securityModulesAvailable.securityLogs) {
            const logs = window.securityLogs.getAllLogs();
            totalLogs = logs.length;
            failedLogins = logs.filter(log => log.status === window.securityLogs.LOG_TYPES.FAILURE).length;
            suspiciousActivities = logs.filter(log => log.status === window.securityLogs.LOG_TYPES.SUSPICIOUS).length;
        }
        
        // Obtenir les statistiques de blocage d'IP
        let blockedIPs = 0;
        if (securityModulesAvailable.loginSecurity) {
            // Dans un environnement réel, on obtiendrait le nombre d'IP bloquées
            // Pour cette démonstration, on utilise une valeur fictive
            blockedIPs = 2;
        }
        
        // Afficher les statistiques
        securityStatsContainer.innerHTML = `
            <div class="stat-card">
                <div class="stat-value">${totalLogs}</div>
                <div class="stat-label">Événements de sécurité</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${failedLogins}</div>
                <div class="stat-label">Tentatives échouées</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${suspiciousActivities}</div>
                <div class="stat-label">Activités suspectes</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${blockedIPs}</div>
                <div class="stat-label">IP bloquées</div>
            </div>
        `;
    }
    
    /**
     * Ajoute les gestionnaires d'événements pour les actions de sécurité
     */
    function addSecurityEventListeners() {
        // Gestionnaire pour le bouton de changement de mode de liste blanche
        const toggleModeBtn = document.getElementById('toggleWhitelistMode');
        if (toggleModeBtn && securityModulesAvailable.ipWhitelist) {
            toggleModeBtn.addEventListener('click', function() {
                const config = window.ipWhitelist.getConfig();
                const newMode = !config.strictMode;
                
                // Dans un environnement réel, on mettrait à jour la configuration
                // Pour cette démonstration, on simule le changement
                alert(`Mode ${newMode ? 'strict' : 'normal'} activé. Dans un environnement réel, ce paramètre serait sauvegardé.`);
                
                // Mettre à jour l'affichage
                const ipWhitelistMode = document.getElementById('ipWhitelistMode');
                if (ipWhitelistMode) {
                    ipWhitelistMode.textContent = newMode ? 'Mode strict' : 'Mode normal';
                    ipWhitelistMode.className = newMode ? 'mode-strict' : 'mode-normal';
                }
            });
        }
        
        // Gestionnaire pour le bouton d'exportation des logs
        const exportLogsBtn = document.getElementById('exportLogs');
        if (exportLogsBtn && securityModulesAvailable.securityLogs) {
            exportLogsBtn.addEventListener('click', function() {
                const format = document.getElementById('exportFormat');
                const formatValue = format ? format.value : 'json';
                
                window.securityLogs.downloadLogs(formatValue);
            });
        }
        
        // Gestionnaire pour le bouton de déconnexion
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn && window.auth) {
            logoutBtn.addEventListener('click', function(e) {
                e.preventDefault();
                window.auth.logout();
            });
        }
    }
    
    /**
     * Affiche une notification à l'utilisateur
     */
    function showNotification(message, type = 'info') {
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
            setTimeout(() => notification.remove(), 500);
        }, 5000);
    }
});