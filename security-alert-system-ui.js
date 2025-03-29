// Interface utilisateur pour le système d'alerte de sécurité de Tech Shield

document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si nous sommes sur la page d'administration
    if (!document.querySelector('.admin-container')) return;
    
    // Vérifier si le système d'alerte est disponible
    if (!window.securityAlertSystem) {
        console.error("Le système d'alerte de sécurité n'est pas disponible");
        return;
    }
    
    // Initialiser l'interface utilisateur du système d'alerte
    initAlertSystemUI();
    
    // Ajouter un onglet pour les alertes dans la navigation de l'administration
    addAlertTabToAdminNav();
});

// Fonction pour initialiser l'interface utilisateur du système d'alerte
function initAlertSystemUI() {
    // Créer le conteneur pour les alertes si nécessaire
    let alertsContainer = document.getElementById('securityAlerts');
    if (!alertsContainer) {
        const adminContent = document.querySelector('.admin-content');
        if (adminContent) {
            alertsContainer = document.createElement('div');
            alertsContainer.id = 'securityAlerts';
            alertsContainer.className = 'admin-section';
            alertsContainer.style.display = 'none'; // Caché par défaut
            adminContent.appendChild(alertsContainer);
        }
    }
    
    if (alertsContainer) {
        // Obtenir les alertes actives
        const activeAlerts = window.securityAlertSystem.getActiveAlerts();
        const alertStats = window.securityAlertSystem.getAlertStats();
        
        // Créer l'interface utilisateur
        alertsContainer.innerHTML = `
            <h2>Alertes de sécurité</h2>
            
            <div class="alert-stats-panel">
                <div class="stat-card">
                    <div class="stat-value">${alertStats.totalAlerts || 0}</div>
                    <div class="stat-label">Alertes totales</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">${activeAlerts.length}</div>
                    <div class="stat-label">Alertes actives</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">${alertStats.bySeverity?.critical || 0}</div>
                    <div class="stat-label">Alertes critiques</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">${alertStats.bySeverity?.high || 0}</div>
                    <div class="stat-label">Alertes élevées</div>
                </div>
            </div>
            
            <div class="alerts-filter-panel">
                <h3>Filtrer les alertes</h3>
                <div class="filter-controls">
                    <div class="filter-group">
                        <label for="severityFilter">Gravité:</label>
                        <select id="severityFilter" class="form-control">
                            <option value="all">Toutes</option>
                            <option value="critical">Critique</option>
                            <option value="high">Élevée</option>
                            <option value="medium">Moyenne</option>
                            <option value="low">Faible</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="typeFilter">Type:</label>
                        <select id="typeFilter" class="form-control">
                            <option value="all">Tous</option>
                            <option value="failed_login_threshold">Tentatives échouées</option>
                            <option value="brute_force_attack">Force brute</option>
                            <option value="suspicious_activity">Activité suspecte</option>
                            <option value="suspicious_login">Connexion suspecte</option>
                            <option value="suspicious_logs">Logs de connexions suspectes</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="dateFilter">Date:</label>
                        <select id="dateFilter" class="form-control">
                            <option value="all">Toutes</option>
                            <option value="today">Aujourd'hui</option>
                            <option value="yesterday">Hier</option>
                            <option value="week">Cette semaine</option>
                            <option value="month">Ce mois</option>
                        </select>
                    </div>
                    
                    <button id="applyFilters" class="btn btn-primary">Appliquer</button>
                    <button id="resetFilters" class="btn btn-secondary">Réinitialiser</button>
                </div>
            </div>
            
            <div class="active-alerts-panel">
                <h3>Alertes actives</h3>
                <div class="alerts-list" id="activeAlertsList">
                    ${activeAlerts.length > 0 ? renderAlertsList(activeAlerts) : '<p class="no-data">Aucune alerte active</p>'}
                </div>
            </div>
            
            <div class="siem-integration-panel">
                <h3>Intégration SIEM</h3>
                <div class="siem-controls">
                    <div class="form-group">
                        <label for="siemType">Type de SIEM:</label>
                        <select id="siemType" class="form-control">
                            <option value="elk">ELK Stack</option>
                            <option value="splunk">Splunk</option>
                            <option value="graylog">Graylog</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <button id="exportSIEMLogs" class="btn btn-primary">Exporter les alertes</button>
                        <button id="sendSIEMLogs" class="btn btn-secondary">Simuler l'envoi</button>
                    </div>
                </div>
            </div>
        `;
        
        // Ajouter les gestionnaires d'événements
        addAlertUIEventListeners();
    }
}

// Fonction pour rendre la liste des alertes
function renderAlertsList(alerts) {
    if (!alerts || alerts.length === 0) {
        return '<p class="no-data">Aucune alerte</p>';
    }
    
    // Trier les alertes par date (les plus récentes en premier)
    const sortedAlerts = [...alerts].sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
    );
    
    return sortedAlerts.map(alert => `
        <div class="alert-item ${alert.severity}" data-alert-id="${alert.id}">
            <div class="alert-header">
                <div class="alert-title">
                    <span class="alert-severity ${alert.severity}">${alert.severity.toUpperCase()}</span>
                    <span class="alert-type">${formatAlertType(alert.type)}</span>
                </div>
                <div class="alert-time">${formatDate(alert.timestamp)}</div>
            </div>
            
            <div class="alert-content">
                <p class="alert-details">${alert.details}</p>
                ${alert.email ? `<p class="alert-user">Utilisateur: ${alert.email}</p>` : ''}
                ${alert.ipAddress ? `<p class="alert-ip">IP: ${alert.ipAddress}</p>` : ''}
            </div>
            
            <div class="alert-actions">
                ${alert.actions && alert.actions.length > 0 ? `
                    <div class="alert-action-list">
                        <h4>Actions effectuées:</h4>
                        <ul>
                            ${alert.actions.map(action => `
                                <li>
                                    <span class="action-type">${formatActionType(action.type)}</span>
                                    <span class="action-time">${formatDate(action.timestamp)}</span>
                                    <span class="action-details">${action.details}</span>
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                ` : ''}
                
                <div class="alert-buttons">
                    <button class="resolve-alert-btn" data-alert-id="${alert.id}">Résoudre</button>
                    <button class="block-ip-btn" data-ip="${alert.ipAddress}" ${!alert.ipAddress ? 'disabled' : ''}>Bloquer IP</button>
                    ${alert.email ? `<button class="lock-account-btn" data-email="${alert.email}">Verrouiller compte</button>` : ''}
                </div>
            </div>
        </div>
    `).join('');
}

// Fonction pour formater le type d'alerte
function formatAlertType(type) {
    const typeLabels = {
        'failed_login_threshold': 'Tentatives de connexion échouées',
        'brute_force_attack': 'Attaque par force brute',
        'suspicious_activity': 'Activité suspecte',
        'geo_location_change': 'Changement de localisation',
        'odd_hour_login': 'Connexion à heure inhabituelle',
        'multi_browser_login': 'Connexions depuis plusieurs navigateurs',
        'suspicious_login': 'Connexion suspecte'
    };
    
    return typeLabels[type] || type;
}

// Fonction pour formater le type d'action
function formatActionType(type) {
    const actionLabels = {
        'block_ip': 'Blocage IP',
        'lock_account': 'Verrouillage compte',
        'require_verification': 'Vérification supplémentaire'
    };
    
    return actionLabels[type] || type;
}

// Fonction pour formater une date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Fonction pour ajouter les gestionnaires d'événements à l'interface utilisateur
function addAlertUIEventListeners() {
    // Gestionnaire pour le bouton d'application des filtres
    const applyFiltersBtn = document.getElementById('applyFilters');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', function() {
            filterAlerts();
        });
    }
    
    // Gestionnaire pour le bouton de réinitialisation des filtres
    const resetFiltersBtn = document.getElementById('resetFilters');
    if (resetFiltersBtn) {
        resetFiltersBtn.addEventListener('click', function() {
            // Réinitialiser les filtres
            document.getElementById('severityFilter').value = 'all';
            document.getElementById('typeFilter').value = 'all';
            document.getElementById('dateFilter').value = 'all';
            
            // Appliquer les filtres réinitialisés
            filterAlerts();
        });
    }
    
    // Gestionnaire pour les boutons de résolution d'alerte
    document.querySelectorAll('.resolve-alert-btn').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-alert-id');
            if (alertId && window.securityAlertSystem.resolveAlert) {
                if (window.securityAlertSystem.resolveAlert(alertId, 'Résolue manuellement par l\'administrateur')) {
                    // Rafraîchir l'interface utilisateur
                    initAlertSystemUI();
                    showNotification('Alerte résolue avec succès', 'success');
                } else {
                    showNotification('Erreur lors de la résolution de l\'alerte', 'error');
                }
            }
        });
    });
    
    // Gestionnaire pour les boutons de blocage d'IP
    document.querySelectorAll('.block-ip-btn').forEach(button => {
        button.addEventListener('click', function() {
            const ipAddress = this.getAttribute('data-ip');
            if (ipAddress && window.securityAlertSystem.blockIP) {
                if (window.securityAlertSystem.blockIP(ipAddress, 60)) { // 60 minutes
                    showNotification(`IP ${ipAddress} bloquée pour 60 minutes`, 'success');
                } else {
                    showNotification(`Erreur lors du blocage de l'IP ${ipAddress}`, 'error');
                }
            }
        });
    });
    
    // Gestionnaire pour les boutons de verrouillage de compte
    document.querySelectorAll('.lock-account-btn').forEach(button => {
        button.addEventListener('click', function() {
            const email = this.getAttribute('data-email');
            if (email && window.securityAlertSystem.lockAccount) {
                if (window.securityAlertSystem.lockAccount(email, 30)) { // 30 minutes
                    showNotification(`Compte ${email} verrouillé pour 30 minutes`, 'success');
                } else {
                    showNotification(`Erreur lors du verrouillage du compte ${email}`, 'error');
                }
            }
        });
    });
    
    // Gestionnaire pour le bouton d'exportation des logs SIEM
    const exportSIEMLogsBtn = document.getElementById('exportSIEMLogs');
    if (exportSIEMLogsBtn) {
        exportSIEMLogsBtn.addEventListener('click', function() {
            const siemType = document.getElementById('siemType').value;
            if (window.siemIntegration && window.siemIntegration.downloadLogs) {
                window.siemIntegration.downloadLogs(siemType);
                showNotification(`Logs exportés au format ${siemType.toUpperCase()}`, 'success');
            } else {
                showNotification('Module d\'intégration SIEM non disponible', 'error');
            }
        });
    }
    
    // Gestionnaire pour le bouton d'envoi des logs SIEM
    const sendSIEMLogsBtn = document.getElementById('sendSIEMLogs');
    if (sendSIEMLogsBtn) {
        sendSIEMLogsBtn.addEventListener('click', function() {
            const siemType = document.getElementById('siemType').value;
            if (window.siemIntegration && window.siemIntegration.sendLogs) {
                const result = window.siemIntegration.sendLogs(siemType);
                if (result.success) {
                    showNotification(`${result.sent} logs envoyés avec succès à ${siemType.toUpperCase()}`, 'success');
                } else {
                    showNotification(`Erreur lors de l'envoi des logs à ${siemType.toUpperCase()}`, 'error');
                }
            } else {
                showNotification('Module d\'intégration SIEM non disponible', 'error');
            }
        });
    }
}

// Fonction pour filtrer les alertes
function filterAlerts() {
    // Obtenir les valeurs des filtres
    const severityFilter = document.getElementById('severityFilter').value;
    const typeFilter = document.getElementById('typeFilter').value;
    const dateFilter = document.getElementById('dateFilter').value;
    
    // Obtenir toutes les alertes
    const allAlerts = window.securityAlertSystem.getActiveAlerts();
    
    // Appliquer les filtres
    const filteredAlerts = allAlerts.filter(alert => {
        // Filtre par gravité
        if (severityFilter !== 'all' && alert.severity !== severityFilter) {
            return false;
        }
        
        // Filtre par type
        if (typeFilter !== 'all' && alert.type !== typeFilter) {
            return false;
        }
        
        // Filtre par date
        if (dateFilter !== 'all') {
            const alertDate = new Date(alert.timestamp);
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            const yesterday = new Date(today);
            yesterday.setDate(yesterday.getDate() - 1);
            
            const weekAgo = new Date(today);
            weekAgo.setDate(weekAgo.getDate() - 7);
            
            const monthAgo = new Date(today);
            monthAgo.setMonth(monthAgo.getMonth() - 1);
            
            switch (dateFilter) {
                case 'today':
                    if (alertDate < today) return false;
                    break;
                case 'yesterday':
                    if (alertDate < yesterday || alertDate >= today) return false;
                    break;
                case 'week':
                    if (alertDate < weekAgo) return false;
                    break;
                case 'month':
                    if (alertDate < monthAgo) return false;
                    break;
            }
        }
        
        return true;
    });
    
    // Mettre à jour la liste des alertes
    const alertsList = document.getElementById('activeAlertsList');
    if (alertsList) {
        alertsList.innerHTML = renderAlertsList(filteredAlerts);
        
        // Réattacher les gestionnaires d'événements
        addAlertUIEventListeners();
    }
}

// Fonction pour ajouter un onglet pour les alertes dans la navigation de l'administration
function addAlertTabToAdminNav() {
    const adminNav = document.querySelector('.admin-nav');
    if (!adminNav) return;
    
    // Vérifier si l'onglet existe déjà
    if (!adminNav.querySelector('[data-tab="alerts"]')) {
        // Créer l'élément de navigation
        const alertNavItem = document.createElement('a');
        alertNavItem.href = '#';
        alertNavItem.setAttribute('data-tab', 'alerts');
        alertNavItem.innerHTML = `
            <i class="fas fa-bell"></i>
            <span>Alertes</span>
            <span class="alert-badge">${window.securityAlertSystem.getActiveAlerts().length}</span>
        `;
        
        // Ajouter l'élément à la navigation
        adminNav.appendChild(alertNavItem);
        
        // Ajouter le gestionnaire d'événements
        alertNavItem.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Masquer toutes les sections
            document.querySelectorAll('.admin-section').forEach(section => {
                section.style.display = 'none';
            });
            
            // Afficher la section des alertes
            const alertsSection = document.getElementById('securityAlerts');
            if (alertsSection) {
                alertsSection.style.display = 'block';
            }
            
            // Mettre à jour la classe active
            document.querySelectorAll('.admin-nav a').forEach(link => {
                link.classList.remove('active');
            });
            this.classList.add('active');
        });
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

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.securityAlertSystemUI = {
    initUI: initAlertSystemUI,
    renderAlertsList: renderAlertsList,
    filterAlerts: filterAlerts,
    showNotification: showNotification
};