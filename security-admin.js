// Module d'administration de la sécurité pour Tech Shield

document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si nous sommes sur la page d'administration
    if (!document.querySelector('.admin-container')) return;
    
    // Vérifier si la configuration de sécurité centralisée est disponible
    if (!window.securityConfig) {
        console.warn('Configuration de sécurité non trouvée, utilisation des paramètres par défaut');
        return;
    }
    
    // Initialiser l'interface d'administration de la sécurité
    initSecurityAdmin();
    
    /**
     * Initialise l'interface d'administration de la sécurité
     */
    function initSecurityAdmin() {
        // Créer les onglets de l'interface d'administration de la sécurité
        createSecurityTabs();
        
        // Initialiser le gestionnaire de liste blanche d'IP
        initIPWhitelistManager();
        
        // Initialiser le gestionnaire de permissions utilisateurs
        initUserPermissionsManager();
        
        // Initialiser le gestionnaire de journaux de sécurité
        // La fonction initSecurityLogsManager a été supprimée car la section des journaux n'existe plus
        
        // Initialiser le gestionnaire d'alertes de sécurité
        initSecurityAlertsManager();
    }
    
    /**
     * Crée les onglets de l'interface d'administration de la sécurité
     */
    function createSecurityTabs() {
        // Vérifier si le conteneur d'onglets existe déjà
        const tabsContainer = document.querySelector('.security-tabs');
        if (tabsContainer) return;
        
        // Trouver le conteneur principal de l'administration
        const adminContainer = document.querySelector('.admin-container');
        if (!adminContainer) return;
        
        // Créer le conteneur d'onglets
        const securityTabsContainer = document.createElement('div');
        securityTabsContainer.className = 'security-tabs';
        
        // Créer les onglets
        securityTabsContainer.innerHTML = `
            <div class="tabs-header">
                <button class="tab-btn active" data-tab="ip-whitelist">Liste blanche d'IP</button>
                <button class="tab-btn" data-tab="user-permissions">Permissions utilisateurs</button>
                <button class="tab-btn" data-tab="security-alerts">Alertes de sécurité</button>
            </div>
            <div class="tabs-content">
                <div id="ip-whitelist" class="tab-content active">
                    <h3>Gestion de la liste blanche d'adresses IP</h3>
                    <div class="whitelist-mode"></div>
                    <div class="add-ip-form">
                        <h4>Ajouter une adresse IP</h4>
                        <form id="addIPForm">
                            <div class="form-row">
                                <input type="text" id="ipAddress" placeholder="Adresse IP" required>
                                <input type="text" id="ipDescription" placeholder="Description" required>
                            </div>
                            <div class="form-row">
                                <label>
                                    <input type="checkbox" id="permanentIP"> Permanent
                                </label>
                                <button type="submit">Ajouter</button>
                            </div>
                        </form>
                    </div>
                    <div class="ip-list">
                        <p>Chargement de la liste blanche d'IP...</p>
                    </div>
                </div>
                <div id="user-permissions" class="tab-content">
                    <h3>Gestion des permissions utilisateurs</h3>
                    <div class="roles-list">
                        <p>Chargement des rôles...</p>
                    </div>
                </div>

                <div id="security-alerts" class="tab-content">
                    <h3>Alertes de sécurité</h3>
                    <div class="alerts-list">
                        <p>Chargement des alertes...</p>
                    </div>
                </div>
            </div>
        `;
        
        // Ajouter le conteneur d'onglets au conteneur principal
        adminContainer.insertBefore(securityTabsContainer, adminContainer.firstChild);
        
        // Ajouter les gestionnaires d'événements pour les onglets
        document.querySelectorAll('.tab-btn').forEach(button => {
            button.addEventListener('click', function() {
                // Désactiver tous les onglets
                document.querySelectorAll('.tab-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.remove('active');
                });
                
                // Activer l'onglet sélectionné
                this.classList.add('active');
                const tabId = this.getAttribute('data-tab');
                document.getElementById(tabId).classList.add('active');
            });
        });
    }
    
    /**
     * Initialise le gestionnaire de liste blanche d'IP
     */
    function initIPWhitelistManager() {
        // Vérifier si le module de liste blanche d'IP est disponible
        if (!window.ipWhitelist) return;
        
        // Mettre à jour l'affichage du mode de liste blanche
        updateWhitelistModeDisplay();
        
        // Charger la liste des IP autorisées
        loadWhitelistedIPs();
        
        // Ajouter un gestionnaire pour le formulaire d'ajout d'IP
        const addIPForm = document.getElementById('addIPForm');
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
                        loadWhitelistedIPs(); // Rafraîchir la liste
                        ipInput.value = '';
                        descriptionInput.value = '';
                        if (permanentCheckbox) permanentCheckbox.checked = false;
                    } else {
                        showNotification(result.reason || 'Erreur lors de l\'ajout de l\'adresse IP', 'error');
                    }
                }
            });
        }
    }
    
    /**
     * Met à jour l'affichage du mode de liste blanche
     */
    function updateWhitelistModeDisplay() {
        const modeContainer = document.querySelector('.whitelist-mode');
        if (!modeContainer || !window.ipWhitelistConfig) return;
        
        const isStrictMode = window.ipWhitelistConfig.strictMode;
        
        modeContainer.className = `whitelist-mode ${isStrictMode ? 'mode-strict' : 'mode-normal'}`;
        modeContainer.innerHTML = `
            <strong>Mode actuel:</strong> ${isStrictMode ? 'Strict' : 'Normal'}
            <p>${isStrictMode ? 'Seules les IP dans la liste blanche sont autorisées pour l\'administration.' : 'Les IP non listées sont autorisées mais surveillées.'}</p>
            <button id="toggleWhitelistMode">${isStrictMode ? 'Passer en mode normal' : 'Passer en mode strict'}</button>
        `;
        
        // Ajouter un gestionnaire pour le bouton de changement de mode
        const toggleButton = document.getElementById('toggleWhitelistMode');
        if (toggleButton) {
            toggleButton.addEventListener('click', function() {
                // Inverser le mode
                window.ipWhitelistConfig.strictMode = !window.ipWhitelistConfig.strictMode;
                
                // Mettre à jour l'affichage
                updateWhitelistModeDisplay();
                
                // Afficher une notification
                showNotification(`Mode de liste blanche changé en mode ${window.ipWhitelistConfig.strictMode ? 'strict' : 'normal'}`, 'info');
            });
        }
    }
    
    /**
     * Charge la liste des IP autorisées
     */
    function loadWhitelistedIPs() {
        const ipListContainer = document.querySelector('.ip-list');
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
    }
    
    /**
     * Supprime une adresse IP de la liste blanche
     */
    function removeIPFromWhitelist(ipAddress) {
        if (!window.ipWhitelist) return;
        
        // Demander confirmation
        if (!confirm(`Êtes-vous sûr de vouloir supprimer l'adresse IP ${ipAddress} de la liste blanche ?`)) {
            return;
        }
        
        // Supprimer l'IP de la liste blanche
        const result = window.ipWhitelist.removeFromWhitelist(ipAddress);
        
        if (result.success) {
            showNotification('Adresse IP supprimée de la liste blanche', 'success');
            loadWhitelistedIPs(); // Rafraîchir la liste
        } else {
            showNotification(result.reason || 'Erreur lors de la suppression de l\'adresse IP', 'error');
        }
    }
    
    /**
     * Valide une adresse IP
     */
    function validateIPAddress(ipAddress) {
        // Regex pour valider une adresse IPv4
        const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipv4Regex.test(ipAddress);
    }
    
    /**
     * Initialise le gestionnaire de permissions utilisateurs
     */
    function initUserPermissionsManager() {
        // Vérifier si le module de permissions utilisateurs est disponible
        if (!window.userPermissions) return;
        
        // Charger la liste des rôles
        loadUserRoles();
    }
    
    /**
     * Charge la liste des rôles utilisateurs
     */
    function loadUserRoles() {
        const rolesListContainer = document.querySelector('.roles-list');
        if (!rolesListContainer || !window.userRoles) return;
        
        // Vider le conteneur
        rolesListContainer.innerHTML = '';
        
        // Créer un tableau pour afficher les rôles et leurs permissions
        const rolesTable = document.createElement('table');
        rolesTable.className = 'roles-table';
        
        // Créer l'en-tête du tableau
        const tableHeader = document.createElement('thead');
        tableHeader.innerHTML = `
            <tr>
                <th>Rôle</th>
                <th>Permissions</th>
            </tr>
        `;
        rolesTable.appendChild(tableHeader);
        
        // Créer le corps du tableau
        const tableBody = document.createElement('tbody');
        
        // Ajouter chaque rôle au tableau
        Object.entries(window.userRoles).forEach(([roleId, roleData]) => {
            const row = document.createElement('tr');
            
            // Créer la cellule pour le nom du rôle
            const roleCell = document.createElement('td');
            roleCell.className = 'role-name';
            roleCell.textContent = roleData.name;
            row.appendChild(roleCell);
            
            // Créer la cellule pour les permissions
            const permissionsCell = document.createElement('td');
            permissionsCell.className = 'role-permissions';
            
            // Créer la liste des permissions
            const permissionsList = document.createElement('ul');
            roleData.permissions.forEach(permission => {
                const permissionItem = document.createElement('li');
                permissionItem.textContent = window.permissionDescriptions[permission] || permission;
                permissionsList.appendChild(permissionItem);
            });
            
            permissionsCell.appendChild(permissionsList);
            row.appendChild(permissionsCell);
            
            tableBody.appendChild(row);
        });
        
        rolesTable.appendChild(tableBody);
        rolesListContainer.appendChild(rolesTable);
    }
    

    
    /**
     * Charge les statistiques de sécurité
     */
    function loadSecurityStats() {
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
    
    /**
     * Charge les journaux de sécurité
     */
    function loadSecurityLogs() {
        const logTableBody = document.querySelector('.log-table tbody');
        if (!logTableBody || !window.securityLogs) return;
        
        // Obtenir les filtres
        const typeFilter = document.getElementById('logTypeFilter').value;
        const searchFilter = document.getElementById('logSearchFilter').value.toLowerCase();
        
        // Obtenir tous les logs
        let logs = window.securityLogs.getAllLogs();
        
        // Appliquer le filtre de type
        if (typeFilter !== 'all') {
            logs = logs.filter(log => log.status === typeFilter);
        }
        
        // Appliquer le filtre de recherche
        if (searchFilter) {
            logs = logs.filter(log => 
                (log.email && log.email.toLowerCase().includes(searchFilter)) ||
                (log.ipAddress && log.ipAddress.toLowerCase().includes(searchFilter)) ||
                (log.details && log.details.toLowerCase().includes(searchFilter))
            );
        }
        
        // Trier les logs par date (du plus récent au plus ancien)
        logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Vider le tableau actuel
        logTableBody.innerHTML = '';
        
        // Afficher un message si aucun log n'est trouvé
        if (logs.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="5">Aucun journal trouvé</td>`;
            logTableBody.appendChild(row);
            return;
        }
        
        // Ajouter chaque log au tableau
        logs.forEach(log => {
            const row = document.createElement('tr');
            
            // Formater la date
            const date = new Date(log.timestamp);
            const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
            
            // Déterminer la classe CSS pour le statut
            let statusClass = 'log-info';
            let statusText = 'Info';
            
            switch(log.status) {
                case window.securityLogs.LOG_TYPES.SUCCESS:
                    statusClass = 'log-success';
                    statusText = 'Succès';
                    break;
                case window.securityLogs.LOG_TYPES.FAILURE:
                    statusClass = 'log-failed';
                    statusText = 'Échec';
                    break;
                case window.securityLogs.LOG_TYPES.SUSPICIOUS:
                    statusClass = 'log-suspicious';
                    statusText = 'Suspect';
                    break;
                case window.securityLogs.LOG_TYPES.WARNING:
                    statusClass = 'log-warning';
                    statusText = 'Avertissement';
                    break;
            }
            
            // Construire la ligne du tableau
            row.innerHTML = `
                <td>${formattedDate}</td>
                <td>${log.email || 'N/A'}</td>
                <td>${log.ipAddress}</td>
                <td><span class="log-status ${statusClass}">${statusText}</span></td>
                <td>${log.details}</td>
            `;
            
            logTableBody.appendChild(row);
        });
    }
    
    /**
     * Initialise le gestionnaire d'alertes de sécurité
     */
    function initSecurityAlertsManager() {
        // Vérifier si le module de journalisation avancée est disponible
        if (!window.advancedSecurityLogs) return;
        
        // Charger les alertes de sécurité
        loadSecurityAlerts();
    }
    
    /**
     * Charge les alertes de sécurité
     */
    function loadSecurityAlerts() {
        const alertsListContainer = document.querySelector('.alerts-list');
        if (!alertsListContainer || !window.advancedSecurityLogs) return;
        
        // Obtenir les alertes actives
        const activeAlerts = window.advancedSecurityLogs.getActiveAlerts();
        
        // Vider le conteneur
        alertsListContainer.innerHTML = '';
        
        // Afficher un message si aucune alerte n'est trouvée
        if (activeAlerts.length === 0) {
            alertsListContainer.innerHTML = '<p class="no-data">Aucune alerte active</p>';
            return;
        }
        
        // Créer la liste des alertes
        const alertsList = document.createElement('div');
        alertsList.className = 'alerts-items';
        
        // Ajouter chaque alerte à la liste
        activeAlerts.forEach(alert => {
            const alertItem = document.createElement('div');
            alertItem.className = `alert-item ${alert.severity}`;
            
            // Formater la date
            const date = new Date(alert.timestamp);
            const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
            
            alertItem.innerHTML = `
                <div class="alert-header">
                    <div class="alert-title">${alert.title}</div>
                    <div class="alert-time">${formattedDate}</div>
                </div>
                <div class="alert-message">${alert.message}</div>
                <div class="alert-actions">
                    <button class="dismiss-alert" data-alert-id="${alert.id}">Ignorer</button>
                </div>
            `;
            
            alertsList.appendChild(alertItem);
        });
        
        alertsListContainer.appendChild(alertsList);
        
        // Ajouter les gestionnaires d'événements pour les boutons d'ignorance
        document.querySelectorAll('.dismiss-alert').forEach(button => {
            button.addEventListener('click', function() {
                const alertId = this.getAttribute('data-alert-id');
                dismissSecurityAlert(alertId);
            });
        });
    }
    
    /**
     * Ignore une alerte de sécurité
     */
    function dismissSecurityAlert(alertId) {
        if (!window.advancedSecurityLogs) return;
        
        // Ignorer l'alerte
        const result = window.advancedSecurityLogs.dismissAlert(alertId);
        
        if (result.success) {
            showNotification('Alerte ignorée', 'success');
            loadSecurityAlerts(); // Rafraîchir la liste
        } else {
            showNotification(result.reason || 'Erreur lors de l\'ignorance de l\'alerte', 'error');
        }
    }
    
    /**
     * Affiche une notification
     */
    function showNotification(message, type = 'info') {
        // Vérifier si la fonction de notification est disponible dans le module de surveillance
        if (window.showSecurityNotification) {
            window.showSecurityNotification(message, type);
            return;
        }
        
        // Sinon, utiliser une alerte simple
        alert(message);
    }
});