// Gestionnaire d'interface pour les alertes de sécurité

document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si nous sommes sur la page d'administration avec l'onglet des alertes
    if (!document.querySelector('#security-alerts')) return;
    
    // Initialiser l'interface des alertes de sécurité
    initSecurityAlertsUI();
    
    // Ajouter les gestionnaires d'événements
    addSecurityAlertsEventListeners();
});

// Fonction pour initialiser l'interface des alertes de sécurité
function initSecurityAlertsUI() {
    console.log('Initialisation de l\'interface des alertes de sécurité...');
    
    // Vérifier si le système d'alerte est disponible
    if (!window.securityAlertSystem) {
        console.error("Le système d'alerte de sécurité n'est pas disponible");
        showErrorMessage("Le système d'alerte de sécurité n'est pas disponible");
        return;
    }
    
    // Charger les statistiques des alertes
    loadAlertStatistics();
    
    // Charger la liste des alertes
    loadAlertsList();
}

// Fonction pour charger les statistiques des alertes
function loadAlertStatistics() {
    try {
        // Obtenir les statistiques des alertes depuis le système d'alerte
        const alertStats = window.securityAlertSystem.getAlertStats();
        const activeAlerts = window.securityAlertSystem.getActiveAlerts();
        
        // Mettre à jour les compteurs dans l'interface
        document.getElementById('total-alerts').textContent = alertStats.totalAlerts || 0;
        document.getElementById('active-alerts').textContent = activeAlerts.length || 0;
        document.getElementById('critical-alerts').textContent = alertStats.bySeverity?.critical || 0;
        document.getElementById('high-alerts').textContent = alertStats.bySeverity?.high || 0;
    } catch (error) {
        console.error('Erreur lors du chargement des statistiques des alertes:', error);
        showErrorMessage("Impossible de charger les statistiques des alertes");
    }
}

// Fonction pour charger la liste des alertes
function loadAlertsList() {
    try {
        const alertsList = document.getElementById('alerts-list');
        if (!alertsList) return;
        
        // Obtenir les alertes depuis le système d'alerte
        const activeAlerts = window.securityAlertSystem.getActiveAlerts();
        
        // Obtenir les logs de connexions suspectes
        const suspiciousLogs = loadSuspiciousLoginLogs();
        
        // Combiner les alertes et les logs
        const allAlerts = [...activeAlerts, ...suspiciousLogs];
        
        // Supprimer le message de chargement
        const loadingElement = alertsList.querySelector('.loading-alerts');
        if (loadingElement) {
            alertsList.removeChild(loadingElement);
        }
        
        // Afficher un message si aucune alerte n'est disponible
        if (!allAlerts || allAlerts.length === 0) {
            alertsList.innerHTML = '<div class="no-alerts">Aucune alerte de sécurité active</div>';
            return;
        }
        
        // Trier les alertes par gravité et date (les plus critiques et récentes en premier)
        const sortedAlerts = [...activeAlerts].sort((a, b) => {
            // Ordre de priorité des niveaux de gravité
            const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
            
            // Comparer d'abord par gravité
            if (severityOrder[a.severity] !== severityOrder[b.severity]) {
                return severityOrder[a.severity] - severityOrder[b.severity];
            }
            
            // Si même gravité, comparer par date (plus récent en premier)
            return new Date(b.timestamp) - new Date(a.timestamp);
        });
        
        // Créer et ajouter les éléments d'alerte à la liste
        sortedAlerts.forEach(alert => {
            const alertElement = createAlertElement(alert);
            alertsList.appendChild(alertElement);
        });
    } catch (error) {
        console.error('Erreur lors du chargement de la liste des alertes:', error);
        showErrorMessage("Impossible de charger la liste des alertes");
    }
}

// Fonction pour créer un élément d'alerte
function createAlertElement(alert) {
    // Cloner le modèle d'alerte
    const template = document.getElementById('alert-template');
    const alertElement = template.content.cloneNode(true).querySelector('.alert-item');
    
    // Définir l'ID de l'alerte
    alertElement.setAttribute('data-alert-id', alert.id);
    
    // Définir la gravité
    const severityElement = alertElement.querySelector('.alert-severity');
    severityElement.textContent = formatSeverity(alert.severity);
    severityElement.classList.add(alert.severity);
    
    // Définir le titre
    alertElement.querySelector('.alert-title').textContent = formatAlertType(alert.type);
    
    // Définir l'heure
    alertElement.querySelector('.alert-time').textContent = formatDate(alert.timestamp);
    
    // Définir la description
    alertElement.querySelector('.alert-description').textContent = alert.details || 'Aucune description disponible';
    
    // Définir les détails
    if (alert.ipAddress) {
        alertElement.querySelector('.ip-address').textContent = alert.ipAddress;
    } else {
        const ipItem = alertElement.querySelector('.detail-item:nth-child(1)');
        ipItem.style.display = 'none';
    }
    
    if (alert.username) {
        alertElement.querySelector('.username').textContent = alert.username;
    } else {
        const userItem = alertElement.querySelector('.detail-item:nth-child(2)');
        userItem.style.display = 'none';
    }
    
    if (alert.location) {
        alertElement.querySelector('.location').textContent = alert.location;
    } else {
        const locationItem = alertElement.querySelector('.detail-item:nth-child(3)');
        locationItem.style.display = 'none';
    }
    
    // Configurer les boutons d'action
    const viewDetailsBtn = alertElement.querySelector('.view-details');
    viewDetailsBtn.addEventListener('click', () => showAlertDetails(alert.id));
    
    const markResolvedBtn = alertElement.querySelector('.mark-resolved');
    markResolvedBtn.addEventListener('click', () => resolveAlert(alert.id));
    
    const blockIPBtn = alertElement.querySelector('.block-ip');
    if (alert.ipAddress) {
        blockIPBtn.addEventListener('click', () => blockIP(alert.ipAddress));
    } else {
        blockIPBtn.disabled = true;
    }
    
    return alertElement;
}

// Fonction pour afficher les détails d'une alerte
function showAlertDetails(alertId) {
    try {
        // Obtenir les détails de l'alerte
        const alert = window.securityAlertSystem.getAlertById(alertId);
        if (!alert) {
            showErrorMessage("Alerte non trouvée");
            return;
        }
        
        // Remplir le modal avec les détails de l'alerte
        const modal = document.getElementById('alert-details-modal');
        const fullDetails = modal.querySelector('.alert-full-details');
        const timeline = modal.querySelector('.timeline');
        
        // Remplir les détails complets
        fullDetails.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">ID:</span>
                <span class="detail-value">${alert.id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Type:</span>
                <span class="detail-value">${formatAlertType(alert.type)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Gravité:</span>
                <span class="detail-value ${alert.severity}">${formatSeverity(alert.severity)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Date:</span>
                <span class="detail-value">${formatDate(alert.timestamp)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Description:</span>
                <span class="detail-value">${alert.details || 'Aucune description disponible'}</span>
            </div>
            ${alert.ipAddress ? `
                <div class="detail-row">
                    <span class="detail-label">Adresse IP:</span>
                    <span class="detail-value">${alert.ipAddress}</span>
                </div>
            ` : ''}
            ${alert.username ? `
                <div class="detail-row">
                    <span class="detail-label">Utilisateur:</span>
                    <span class="detail-value">${alert.username}</span>
                </div>
            ` : ''}
            ${alert.location ? `
                <div class="detail-row">
                    <span class="detail-label">Localisation:</span>
                    <span class="detail-value">${alert.location}</span>
                </div>
            ` : ''}
            ${alert.userAgent ? `
                <div class="detail-row">
                    <span class="detail-label">Agent utilisateur:</span>
                    <span class="detail-value">${alert.userAgent}</span>
                </div>
            ` : ''}
        `;
        
        // Remplir la chronologie
        if (alert.timeline && alert.timeline.length > 0) {
            timeline.innerHTML = alert.timeline.map(event => `
                <div class="timeline-item">
                    <div class="timeline-time">${formatDate(event.timestamp)}</div>
                    <div class="timeline-content">${event.description}</div>
                </div>
            `).join('');
        } else {
            timeline.innerHTML = '<div class="no-data">Aucun événement dans la chronologie</div>';
        }
        
        // Configurer les boutons du modal
        const resolveBtn = modal.querySelector('.resolve-btn');
        resolveBtn.onclick = () => {
            resolveAlert(alertId);
            closeModal();
        };
        
        const blockBtn = modal.querySelector('.block-btn');
        if (alert.ipAddress) {
            blockBtn.onclick = () => {
                blockIP(alert.ipAddress);
                closeModal();
            };
            blockBtn.disabled = false;
        } else {
            blockBtn.disabled = true;
        }
        
        // Afficher le modal
        modal.style.display = 'block';
        
        // Configurer le bouton de fermeture
        const closeBtn = modal.querySelector('.close-modal');
        closeBtn.onclick = closeModal;
        
        const closeBtnFooter = modal.querySelector('.close-btn');
        closeBtnFooter.onclick = closeModal;
        
        // Fermer le modal en cliquant en dehors
        window.onclick = function(event) {
            if (event.target === modal) {
                closeModal();
            }
        };
    } catch (error) {
        console.error('Erreur lors de l\'affichage des détails de l\'alerte:', error);
        showErrorMessage("Impossible d'afficher les détails de l'alerte");
    }
}

// Fonction pour fermer le modal
function closeModal() {
    const modal = document.getElementById('alert-details-modal');
    modal.style.display = 'none';
}

// Fonction pour résoudre une alerte
function resolveAlert(alertId) {
    try {
        if (window.securityAlertSystem.resolveAlert) {
            const result = window.securityAlertSystem.resolveAlert(alertId, 'Résolue manuellement par l\'administrateur');
            if (result) {
                // Rafraîchir l'interface
                loadAlertStatistics();
                loadAlertsList();
                showSuccessMessage('Alerte résolue avec succès');
            } else {
                showErrorMessage('Erreur lors de la résolution de l\'alerte');
            }
        } else {
            showErrorMessage('La fonction de résolution d\'alerte n\'est pas disponible');
        }
    } catch (error) {
        console.error('Erreur lors de la résolution de l\'alerte:', error);
        showErrorMessage("Impossible de résoudre l'alerte");
    }
}

// Fonction pour bloquer une adresse IP
function blockIP(ipAddress) {
    try {
        if (window.securityAlertSystem.blockIP) {
            const result = window.securityAlertSystem.blockIP(ipAddress, 60); // 60 minutes
            if (result) {
                showSuccessMessage(`IP ${ipAddress} bloquée pour 60 minutes`);
            } else {
                showErrorMessage(`Erreur lors du blocage de l'IP ${ipAddress}`);
            }
        } else {
            showErrorMessage('La fonction de blocage d\'IP n\'est pas disponible');
        }
    } catch (error) {
        console.error('Erreur lors du blocage de l\'IP:', error);
        showErrorMessage("Impossible de bloquer l'IP");
    }
}

// Fonction pour ajouter les gestionnaires d'événements
function addSecurityAlertsEventListeners() {
    // Gestionnaire pour le bouton d'application des filtres
    const applyFiltersBtn = document.getElementById('applyFilters');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', applyFilters);
    }
    
    // Gestionnaire pour le bouton de réinitialisation des filtres
    const resetFiltersBtn = document.getElementById('resetFilters');
    if (resetFiltersBtn) {
        resetFiltersBtn.addEventListener('click', resetFilters);
    }
}

// Fonction pour charger les logs de connexions suspectes
function loadSuspiciousLoginLogs() {
    try {
        // Vérifier si le module de logs de sécurité est disponible
        if (!window.securityLogs) {
            console.error("Le module de journalisation de sécurité n'est pas disponible");
            return [];
        }
        
        // Obtenir les logs de connexions suspectes
        const suspiciousLogs = window.securityLogs.getLogsByType(window.securityLogs.LOG_TYPES.SUSPICIOUS);
        
        // Convertir les logs en format d'alerte
        return suspiciousLogs.map(log => {
            return {
                id: 'log-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
                type: 'suspicious_login',
                severity: 'medium',
                timestamp: log.timestamp,
                details: log.details,
                ipAddress: log.ipAddress,
                username: log.email,
                location: log.location || 'Inconnue',
                userAgent: log.userAgent || 'Inconnu',
                timeline: [{
                    timestamp: log.timestamp,
                    description: log.details
                }]
            };
        });
    } catch (error) {
        console.error('Erreur lors du chargement des logs de connexions suspectes:', error);
        return [];
    }
}

// Fonction pour appliquer les filtres
function applyFilters() {
    try {
        const severityFilter = document.getElementById('severityFilter').value;
        const typeFilter = document.getElementById('typeFilter').value;
        const statusFilter = document.getElementById('statusFilter').value;
        const dateFilter = document.getElementById('dateFilter').value;
        
        // Obtenir toutes les alertes
        let alerts = [];
        if (statusFilter === 'active' || statusFilter === 'all') {
            alerts = [...alerts, ...window.securityAlertSystem.getActiveAlerts()];
        }
        if (statusFilter === 'resolved' || statusFilter === 'all') {
            alerts = [...alerts, ...window.securityAlertSystem.getResolvedAlerts()];
        }
        
        // Ajouter les logs de connexions suspectes si le filtre est approprié
        if ((typeFilter === 'all' || typeFilter === 'suspicious_login') && 
            (statusFilter === 'all' || statusFilter === 'active')) {
            const suspiciousLogs = loadSuspiciousLoginLogs();
            alerts = [...alerts, ...suspiciousLogs];
        }
        
        // Appliquer les filtres
        const filteredAlerts = alerts.filter(alert => {
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
                
                const weekStart = new Date(today);
                weekStart.setDate(weekStart.getDate() - weekStart.getDay());
                
                const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);
                
                switch (dateFilter) {
                    case 'today':
                        return alertDate >= today;
                    case 'yesterday':
                        return alertDate >= yesterday && alertDate < today;
                    case 'week':
                        return alertDate >= weekStart;
                    case 'month':
                        return alertDate >= monthStart;
                    default:
                        return true;
                }
            }
            
            return true;
        });
        
        // Afficher les alertes filtrées
        displayFilteredAlerts(filteredAlerts);
    } catch (error) {
        console.error('Erreur lors de l\'application des filtres:', error);
        showErrorMessage("Impossible d'appliquer les filtres");
    }
}

// Fonction pour réinitialiser les filtres
function resetFilters() {
    // Réinitialiser les valeurs des filtres
    document.getElementById('severityFilter').value = 'all';
    document.getElementById('typeFilter').value = 'all';
    document.getElementById('statusFilter').value = 'all';
    document.getElementById('dateFilter').value = 'all';
    
    // Recharger la liste des alertes
    loadAlertsList();
}

// Fonction pour afficher les alertes filtrées
function displayFilteredAlerts(filteredAlerts) {
    const alertsList = document.getElementById('alerts-list');
    if (!alertsList) return;
    
    // Vider la liste
    alertsList.innerHTML = '';
    
    // Afficher un message si aucune alerte ne correspond aux filtres
    if (!filteredAlerts || filteredAlerts.length === 0) {
        alertsList.innerHTML = '<div class="no-alerts">Aucune alerte ne correspond aux filtres</div>';
        return;
    }
    
    // Trier les alertes par gravité et date
    const sortedAlerts = [...filteredAlerts].sort((a, b) => {
        // Ordre de priorité des niveaux de gravité
        const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
        
        // Comparer d'abord par gravité
        if (severityOrder[a.severity] !== severityOrder[b.severity]) {
            return severityOrder[a.severity] - severityOrder[b.severity];
        }
        
        // Si même gravité, comparer par date (plus récent en premier)
        return new Date(b.timestamp) - new Date(a.timestamp);
    });
    
    // Créer et ajouter les éléments d'alerte à la liste
    sortedAlerts.forEach(alert => {
        const alertElement = createAlertElement(alert);
        alertsList.appendChild(alertElement);
    });
}

// Fonction pour formater la gravité
function formatSeverity(severity) {
    const severityLabels = {
        'critical': 'CRITIQUE',
        'high': 'ÉLEVÉE',
        'medium': 'MOYENNE',
        'low': 'FAIBLE'
    };
    
    return severityLabels[severity] || severity.toUpperCase();
}

// Fonction pour formater le type d'alerte
function formatAlertType(type) {
    const typeLabels = {
        'failed_login_threshold': 'Tentatives de connexion échouées',
        'brute_force_attack': 'Attaque par force brute',
        'suspicious_activity': 'Activité suspecte',
        'multi_country_login': 'Connexions multi-pays',
        'geo_location_change': 'Changement de localisation',
        'odd_hour_login': 'Connexion à heure inhabituelle',
        'multi_browser_login': 'Connexions depuis plusieurs navigateurs',
        'suspicious_ip_login': 'Connexion depuis une IP inconnue',
        'suspicious_login': 'Connexion suspecte',
        'suspicious_logs': 'Logs de connexions suspectes'
    };
    
    return typeLabels[type] || type;
}

// Fonction pour formater une date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('fr-FR', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// Fonction pour afficher un message d'erreur
function showErrorMessage(message) {
    // Vérifier si le système de notification est disponible
    if (window.showNotification) {
        window.showNotification(message, 'error');
    } else {
        alert(`Erreur: ${message}`);
    }
}

// Fonction pour afficher un message de succès
function showSuccessMessage(message) {
    // Vérifier si le système de notification est disponible
    if (window.showNotification) {
        window.showNotification(message, 'success');
    } else {
        alert(`Succès: ${message}`);
    }
}