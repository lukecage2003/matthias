document.addEventListener("DOMContentLoaded", function() {
    // Charger le module de logs de sécurité si nécessaire
    if (!document.querySelector('script[src="security-logs.js"]')) {
        const script = document.createElement('script');
        script.src = 'security-logs.js';
        script.defer = true;
        document.head.appendChild(script);
    }
    
    // Protéger la page d'administration
    if (window.auth) {
        window.auth.protectAdminPage();
    } else {
        window.location.href = 'login.html';
        return;
    }
    
    // Gestion des onglets de l'interface d'administration
    const tabLinks = document.querySelectorAll('.admin-nav a');
    const tabContents = document.querySelectorAll('.admin-tab');

    tabLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Retirer la classe active de tous les liens et contenus
            tabLinks.forEach(l => l.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Ajouter la classe active au lien cliqué
            this.classList.add('active');
            
            // Afficher le contenu correspondant
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Gestion des onglets de sécurité
    const securityTabBtns = document.querySelectorAll('.tab-btn');
    const securityTabContents = document.querySelectorAll('.tab-content');
    
    securityTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            // Désactiver tous les onglets
            securityTabBtns.forEach(b => b.classList.remove('active'));
            securityTabContents.forEach(c => c.classList.remove('active'));
            
            // Activer l'onglet sélectionné
            this.classList.add('active');
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Initialiser les fonctionnalités de sécurité
    initSecurityFeatures();
    
    // Ajouter les gestionnaires d'événements pour les filtres de logs
    document.getElementById('applyLogFilters')?.addEventListener('click', filterSecurityLogs);
    document.getElementById('resetLogFilters')?.addEventListener('click', function() {
        // Réinitialiser les filtres
        document.getElementById('logTypeFilter').value = 'all';
        document.getElementById('logDateFilter').value = 'all';
        document.getElementById('logUserFilter').value = '';
        document.getElementById('logIPFilter').value = '';
        
        // Recharger les logs sans filtre
        loadSecurityLogs();
    });
    
    // Ajouter les gestionnaires d'événements pour l'exportation et la suppression des logs
    document.getElementById('exportLogs')?.addEventListener('click', exportSecurityLogs);
    document.getElementById('clearLogs')?.addEventListener('click', clearSecurityLogs);
    
    // Ajouter le gestionnaire d'événements pour la déconnexion
    document.getElementById('logoutBtn')?.addEventListener('click', function(e) {
        e.preventDefault();
        if (window.auth && window.auth.logout) {
            window.auth.logout();
        }
    });
});

/**
 * Initialise les fonctionnalités de sécurité
 */
function initSecurityFeatures() {
    // Charger les logs de sécurité
    loadSecurityLogs();
    
    // Charger les alertes de sécurité
    loadSecurityAlerts();
    
    // Mettre à jour les statistiques de sécurité
    updateSecurityStats();
}

/**
 * Charge et affiche les logs de sécurité
 */
function loadSecurityLogs() {
    const logTableBody = document.getElementById('securityLogsTableBody');
    if (!logTableBody || !window.securityLogs) {
        if (logTableBody) {
            logTableBody.innerHTML = '<tr><td colspan="5" class="no-data">Module de logs non disponible</td></tr>';
        }
        return;
    }
    
    // S'assurer que les logs sont chargés depuis le localStorage
    window.securityLogs.loadLogsFromStorage();
    
    // Obtenir tous les logs
    let logs = window.securityLogs.getAllLogs();
    
    // Afficher les logs
    if (logs.length === 0) {
        logTableBody.innerHTML = '<tr><td colspan="5" class="no-data">Aucun log disponible</td></tr>';
    } else {
        // Trier les logs par date (les plus récents en premier)
        const sortedLogs = [...logs].sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        
        // Limiter à 100 logs récents
        const recentLogs = sortedLogs.slice(0, 100);
        
        // Générer le HTML pour les logs
        logTableBody.innerHTML = recentLogs.map(log => {
            // Déterminer la classe CSS en fonction du statut
            let statusClass = '';
            switch(log.status) {
                case window.securityLogs.LOG_TYPES.SUCCESS:
                    statusClass = 'success';
                    break;
                case window.securityLogs.LOG_TYPES.FAILURE:
                    statusClass = 'failure';
                    break;
                case window.securityLogs.LOG_TYPES.SUSPICIOUS:
                    statusClass = 'suspicious';
                    break;
                case window.securityLogs.LOG_TYPES.WARNING:
                    statusClass = 'warning';
                    break;
                case window.securityLogs.LOG_TYPES.CRITICAL:
                    statusClass = 'critical';
                    break;
                default:
                    statusClass = 'info';
            }
            
            // Formatage de l'heure, adresse IP et email pour une meilleure visibilité
            const formattedTime = new Date(log.timestamp).toLocaleString();
            const formattedEmail = log.email || 'N/A';
            const formattedIP = log.ipAddress;
            
            return `
                <tr class="log-row ${statusClass}">
                    <td><strong>${formattedTime}</strong></td>
                    <td><strong>${formattedEmail}</strong></td>
                    <td><strong>${formattedIP}</strong></td>
                    <td><span class="log-status ${statusClass}">${log.status}</span></td>
                    <td>${log.details}</td>
                </tr>
            `;
        }).join('');
    }
}

/**
 * Charge et affiche les alertes de sécurité
 */
function loadSecurityAlerts() {
    const alertsContainer = document.getElementById('securityAlerts');
    if (!alertsContainer || !window.securityLogs) {
        if (alertsContainer) {
            alertsContainer.innerHTML = '<p class="no-data">Module d\'alertes non disponible</p>';
        }
        return;
    }
    
    // Obtenir les alertes actives
    const activeAlerts = window.securityLogs.getActiveAlerts();
    
    // Afficher les alertes
    if (activeAlerts.length === 0) {
        alertsContainer.innerHTML = '<p class="no-data">Aucune alerte active</p>';
    } else {
        // Trier les alertes par date (les plus récentes en premier)
        const sortedAlerts = [...activeAlerts].sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        
        // Générer le HTML pour les alertes
        alertsContainer.innerHTML = sortedAlerts.map(alert => {
            return `
                <div class="alert-item ${alert.severity}" data-alert-id="${alert.id}">
                    <div class="alert-header">
                        <h4 class="alert-title">${alert.title}</h4>
                        <span class="alert-timestamp">${new Date(alert.timestamp).toLocaleString()}</span>
                    </div>
                    <div class="alert-description">${alert.description}</div>
                    <div class="alert-footer">
                        <span class="alert-severity ${alert.severity}">${alert.severity}</span>
                        <div class="alert-actions">
                            <button class="resolve-alert" data-alert-id="${alert.id}">Résoudre</button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
        // Ajouter les gestionnaires d'événements pour les boutons de résolution
        document.querySelectorAll('.resolve-alert').forEach(button => {
            button.addEventListener('click', function() {
                const alertId = this.getAttribute('data-alert-id');
                resolveSecurityAlert(alertId);
            });
        });
    }
}

/**
 * Résout une alerte de sécurité
 * @param {string} alertId - ID de l'alerte à résoudre
 */
function resolveSecurityAlert(alertId) {
    if (!window.securityLogs) return;
    
    const resolution = prompt('Veuillez entrer une description de la résolution:');
    if (resolution !== null) {
        const result = window.securityLogs.resolveAlert(alertId, resolution);
        if (result) {
            // Recharger les alertes et mettre à jour les statistiques
            loadSecurityAlerts();
            updateSecurityStats();
        }
    }
}

/**
 * Met à jour les statistiques de sécurité
 */
function updateSecurityStats() {
    const successLoginsEl = document.getElementById('successLogins');
    const failedLoginsEl = document.getElementById('failedLogins');
    const suspiciousActivitiesEl = document.getElementById('suspiciousActivities');
    const activeAlertsEl = document.getElementById('activeAlerts');
    
    if (!successLoginsEl || !failedLoginsEl || !suspiciousActivitiesEl || !activeAlertsEl || !window.securityLogs) {
        return;
    }
    
    // Obtenir les logs
    const logs = window.securityLogs.getAllLogs();
    
    // Calculer les statistiques
    const successLogins = logs.filter(log => log.status === window.securityLogs.LOG_TYPES.SUCCESS).length;
    const failedLogins = logs.filter(log => log.status === window.securityLogs.LOG_TYPES.FAILURE).length;
    const suspiciousActivities = logs.filter(log => 
        log.status === window.securityLogs.LOG_TYPES.SUSPICIOUS || 
        log.status === window.securityLogs.LOG_TYPES.WARNING
    ).length;
    
    // Obtenir le nombre d'alertes actives
    const activeAlerts = window.securityLogs.getActiveAlerts().length;
    
    // Mettre à jour les éléments HTML
    successLoginsEl.textContent = successLogins;
    failedLoginsEl.textContent = failedLogins;
    suspiciousActivitiesEl.textContent = suspiciousActivities;
    activeAlertsEl.textContent = activeAlerts;
}

/**
 * Filtre les logs de sécurité selon les critères sélectionnés
 */
function filterSecurityLogs() {
    const logTableBody = document.getElementById('securityLogsTableBody');
    if (!logTableBody || !window.securityLogs) return;
    
    // Obtenir les valeurs des filtres
    const typeFilter = document.getElementById('logTypeFilter').value;
    const dateFilter = document.getElementById('logDateFilter').value;
    const userFilter = document.getElementById('logUserFilter').value.toLowerCase();
    const ipFilter = document.getElementById('logIPFilter').value.toLowerCase();
    
    // Obtenir tous les logs
    let logs = window.securityLogs.getAllLogs();
    
    // Appliquer les filtres
    if (typeFilter !== 'all') {
        logs = logs.filter(log => log.status === typeFilter);
    }
    
    if (dateFilter !== 'all') {
        const now = new Date();
        let startDate;
        
        switch(dateFilter) {
            case 'today':
                startDate = new Date(now.setHours(0, 0, 0, 0));
                break;
            case 'yesterday':
                startDate = new Date(now.setDate(now.getDate() - 1));
                startDate.setHours(0, 0, 0, 0);
                break;
            case 'week':
                startDate = new Date(now.setDate(now.getDate() - 7));
                break;
            case 'month':
                startDate = new Date(now.setDate(now.getDate() - 30));
                break;
        }
        
        logs = logs.filter(log => new Date(log.timestamp) >= startDate);
    }
    
    if (userFilter) {
        logs = logs.filter(log => log.email && log.email.toLowerCase().includes(userFilter));
    }
    
    if (ipFilter) {
        logs = logs.filter(log => log.ipAddress && log.ipAddress.toLowerCase().includes(ipFilter));
    }
    
    // Afficher les logs filtrés
    if (logs.length === 0) {
        logTableBody.innerHTML = '<tr><td colspan="5" class="no-data">Aucun log ne correspond aux critères</td></tr>';
    } else {
        // Trier les logs par date (les plus récents en premier)
        const sortedLogs = [...logs].sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        
        // Limiter à 100 logs récents
        const recentLogs = sortedLogs.slice(0, 100);
        
        // Générer le HTML pour les logs
        logTableBody.innerHTML = recentLogs.map(log => {
            // Déterminer la classe CSS en fonction du statut
            let statusClass = '';
            switch(log.status) {
                case window.securityLogs.LOG_TYPES.SUCCESS:
                    statusClass = 'success';
                    break;
                case window.securityLogs.LOG_TYPES.FAILURE:
                    statusClass = 'failure';
                    break;
                case window.securityLogs.LOG_TYPES.SUSPICIOUS:
                    statusClass = 'suspicious';
                    break;
                case window.securityLogs.LOG_TYPES.WARNING:
                    statusClass = 'warning';
                    break;
                case window.securityLogs.LOG_TYPES.CRITICAL:
                    statusClass = 'critical';
                    break;
                default:
                    statusClass = 'info';
            }
            
            // Formatage de l'heure, adresse IP et email pour une meilleure visibilité
            const formattedTime = new Date(log.timestamp).toLocaleString();
            const formattedEmail = log.email || 'N/A';
            const formattedIP = log.ipAddress;
            
            return `
                <tr class="log-row ${statusClass}">
                    <td><strong>${formattedTime}</strong></td>
                    <td><strong>${formattedEmail}</strong></td>
                    <td><strong>${formattedIP}</strong></td>
                    <td><span class="log-status ${statusClass}">${log.status}</span></td>
                    <td>${log.details}</td>
                </tr>
            `;
        }).join('');
    }
}

/**
 * Exporte les logs de sécurité dans le format sélectionné
 */
function exportSecurityLogs() {
    if (!window.securityLogs) return;
    
    // Obtenir tous les logs
    const logs = window.securityLogs.getAllLogs();
    if (logs.length === 0) {
        alert('Aucun log à exporter');
        return;
    }
    
    // Obtenir le format d'exportation
    const format = document.getElementById('exportFormat').value;
    let exportData;
    let mimeType;
    let fileName;
    
    switch(format) {
        case 'json':
            exportData = JSON.stringify(logs, null, 2);
            mimeType = 'application/json';
            fileName = 'security-logs.json';
            break;
        case 'csv':
            // Créer l'en-tête CSV
            const headers = ['Date', 'Utilisateur', 'Adresse IP', 'Statut', 'Détails'];
            // Convertir les logs en lignes CSV
            const csvRows = logs.map(log => {
                const formattedTime = new Date(log.timestamp).toLocaleString();
                const formattedEmail = log.email || 'N/A';
                return `"${formattedTime}","${formattedEmail}","${log.ipAddress}","${log.status}","${log.details.replace(/"/g, '""')}"`;
            });
            // Combiner l'en-tête et les lignes
            exportData = [headers.join(','), ...csvRows].join('\n');
            mimeType = 'text/csv';
            fileName = 'security-logs.csv';
            break;
        case 'siem':
            // Format compatible avec les systèmes SIEM
            exportData = logs.map(log => {
                return {
                    timestamp: log.timestamp,
                    source: 'Tech Shield',
                    sourceType: 'WebApp',
                    event: 'Authentication',
                    severity: log.status === 'success' ? 'info' : 
                             log.status === 'failure' ? 'warning' : 
                             log.status === 'suspicious' ? 'warning' : 
                             log.status === 'critical' ? 'critical' : 'info',
                    user: log.email || 'unknown',
                    ip: log.ipAddress,
                    status: log.status,
                    details: log.details
                };
            });
            exportData = JSON.stringify(exportData, null, 2);
            mimeType = 'application/json';
            fileName = 'security-logs-siem.json';
            break;
    }
    
    // Créer un lien de téléchargement
    const blob = new Blob([exportData], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    
    // Libérer l'URL
    setTimeout(() => URL.revokeObjectURL(url), 100);
}

/**
 * Efface tous les logs de sécurité
 */
function clearSecurityLogs() {
    if (!window.securityLogs) return;
    
    if (confirm('Êtes-vous sûr de vouloir effacer tous les logs de sécurité ? Cette action est irréversible.')) {
        window.securityLogs.clearAllLogs();
        loadSecurityLogs();
        updateSecurityStats();
    }
}