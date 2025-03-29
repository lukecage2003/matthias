// Fichier d'initialisation du système de sécurité complet pour Tech Shield
// Ce fichier intègre tous les modules de sécurité et les initialise

document.addEventListener('DOMContentLoaded', function() {
    console.log('Initialisation du système de sécurité Tech Shield...');
    
    // S'assurer que les modules de sécurité sont chargés
    // Vérifier si window.securityLogs existe, sinon l'initialiser
    if (!window.securityLogs && typeof addLoginLog === 'function') {
        console.log('Initialisation de window.securityLogs...');
        window.securityLogs = {
            LOG_TYPES,
            addLoginLog,
            getAllLogs,
            getLogsByType,
            getLogsByUser,
            getLogsByIP,
            isIPSuspicious,
            clearAllLogs,
            subscribeToLoginEvents,
            unsubscribeFromLoginEvents,
            createSecurityAlert,
            getActiveAlerts,
            resolveAlert,
            subscribeToAlertEvents,
            unsubscribeFromAlertEvents,
            blockIP,
            isIPBlocked,
            exportLogsToJSON,
            exportLogsToCSV,
            exportLogsForSIEM,
            downloadLogs,
            saveLogsToStorage,
            loadLogsFromStorage
        };
    }
    
    // Vérifier quels modules sont disponibles
    const securityModulesAvailable = {
        securityLogs: !!window.securityLogs,
        advancedSecurityLogs: !!window.advancedSecurityLogs,
        siemIntegration: !!window.siemIntegration,
        securityAlertSystem: !!window.securityAlertSystem,
        securityMonitoring: !!window.securityMonitoring
    };
    
    // Afficher les modules disponibles dans la console
    console.log('Modules de sécurité disponibles:', securityModulesAvailable);
    
    // Initialiser le système d'alerte si disponible
    if (securityModulesAvailable.securityAlertSystem) {
        console.log('Initialisation du système d\'alerte...');
        window.securityAlertSystem.initAlertSystem();
    } else {
        console.warn('Le système d\'alerte n\'est pas disponible');
    }
    
    // Initialiser l'intégration SIEM si disponible
    if (securityModulesAvailable.siemIntegration) {
        console.log('Initialisation de l\'intégration SIEM...');
        // L'initialisation se fait automatiquement dans le module
    } else {
        console.warn('L\'intégration SIEM n\'est pas disponible');
    }
    
    // Initialiser le système de surveillance si disponible
    if (securityModulesAvailable.securityMonitoring) {
        console.log('Initialisation du système de surveillance...');
        // L'initialisation se fait automatiquement dans le module
    } else {
        console.warn('Le système de surveillance n\'est pas disponible');
    }
    
    // Initialiser l'interface utilisateur si nous sommes sur la page d'administration
    if (document.querySelector('.admin-container')) {
        initSecurityUI(securityModulesAvailable);
    }
    
    // Configurer les gestionnaires d'événements pour les formulaires de connexion
    setupLoginFormHandlers();
});

// Fonction pour initialiser l'interface utilisateur de sécurité
function initSecurityUI(availableModules) {
    console.log('Initialisation de l\'interface utilisateur de sécurité...');
    
    // Initialiser l'interface du système d'alerte si disponible
    if (availableModules.securityAlertSystem && window.securityAlertSystemUI) {
        window.securityAlertSystemUI.initUI();
    }
    
    // Initialiser l'interface d'intégration SIEM si disponible
    if (availableModules.siemIntegration && window.siemIntegration.initUI) {
        window.siemIntegration.initUI();
    }
    
    // Ajouter un onglet pour les logs de sécurité dans la navigation de l'administration
    addSecurityTabToAdminNav();
}

// Fonction pour ajouter un onglet pour les logs de sécurité dans la navigation de l'administration
function addSecurityTabToAdminNav() {
    const adminNav = document.querySelector('.admin-nav');
    if (!adminNav) return;
    
    // Vérifier si l'onglet existe déjà
    if (!adminNav.querySelector('[data-tab="security"]')) {
        // Créer l'élément de navigation
        const securityNavItem = document.createElement('a');
        securityNavItem.href = '#';
        securityNavItem.setAttribute('data-tab', 'security');
        securityNavItem.innerHTML = `
            <i class="fas fa-shield-alt"></i>
            <span>Sécurité</span>
        `;
        
        // Ajouter l'élément à la navigation
        adminNav.appendChild(securityNavItem);
        
        // Ajouter le gestionnaire d'événements
        securityNavItem.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Masquer toutes les sections
            document.querySelectorAll('.admin-section').forEach(section => {
                section.style.display = 'none';
            });
            
            // Afficher la section de sécurité
            const securitySection = document.getElementById('securityDashboard');
            if (securitySection) {
                securitySection.style.display = 'block';
            } else {
                // Créer la section si elle n'existe pas
                createSecurityDashboard();
            }
            
            // Mettre à jour la classe active
            document.querySelectorAll('.admin-nav a').forEach(link => {
                link.classList.remove('active');
            });
            this.classList.add('active');
        });
    }
}

// Fonction pour créer le tableau de bord de sécurité
function createSecurityDashboard() {
    const adminContent = document.querySelector('.admin-content');
    if (!adminContent) return;
    
    // Créer la section de sécurité
    const securitySection = document.createElement('div');
    securitySection.id = 'securityDashboard';
    securitySection.className = 'admin-section';
    
    // Construire le contenu du tableau de bord
    securitySection.innerHTML = `
        <h2>Tableau de bord de sécurité</h2>
        
        <div class="security-dashboard-grid">
            <!-- Statistiques de sécurité -->
            <div class="dashboard-card" id="securityStats">
                <h3>Statistiques</h3>
                <div class="stats-container">
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
            </div>
            
            <!-- Alertes récentes -->
            <div class="dashboard-card" id="recentAlerts">
                <h3>Alertes récentes</h3>
                <div class="alerts-container" id="recentAlertsContainer">
                    <p class="no-data">Chargement des alertes...</p>
                </div>
            </div>
            
            <!-- Intégration SIEM -->
            <div class="dashboard-card" id="siemIntegration">
                <h3>Intégration SIEM</h3>
                <div class="siem-container">
                    <div class="form-group">
                        <label for="siemType">Type de SIEM:</label>
                        <select id="siemType" class="form-control">
                            <option value="elk">ELK Stack</option>
                            <option value="splunk">Splunk</option>
                            <option value="graylog">Graylog</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <button id="exportSIEMLogs" class="btn btn-primary">Exporter les logs</button>
                        <button id="sendSIEMLogs" class="btn btn-secondary">Simuler l'envoi</button>
                    </div>
                </div>
            </div>
            
            <!-- Système d'alerte -->
            <div class="dashboard-card" id="alertSystem">
                <h3>Système d'alerte</h3>
                <div class="alert-system-container">
                    <p>Configuration du système d'alerte:</p>
                    <div class="form-group">
                        <label for="failedLoginThreshold">Seuil de tentatives échouées:</label>
                        <input type="number" id="failedLoginThreshold" class="form-control" value="5" min="1" max="10">
                    </div>
                    
                    <div class="form-group">
                        <label for="timeWindowMinutes">Fenêtre de temps (minutes):</label>
                        <input type="number" id="timeWindowMinutes" class="form-control" value="15" min="1" max="60">
                    </div>
                    
                    <div class="form-group">
                        <button id="saveAlertConfig" class="btn btn-primary">Enregistrer</button>
                        <button id="testAlert" class="btn btn-secondary">Tester une alerte</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Journaux de sécurité -->
        <div class="security-logs-panel">
            <h3>Journaux de sécurité</h3>
            
            <div class="logs-filter-panel">
                <div class="filter-controls">
                    <div class="filter-group">
                        <label for="logTypeFilter">Type:</label>
                        <select id="logTypeFilter" class="form-control">
                            <option value="all">Tous</option>
                            <option value="success">Succès</option>
                            <option value="failure">Échec</option>
                            <option value="suspicious">Suspect</option>
                            <option value="warning">Avertissement</option>
                            <option value="critical">Critique</option>
                            <option value="info">Information</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="logDateFilter">Date:</label>
                        <select id="logDateFilter" class="form-control">
                            <option value="all">Toutes</option>
                            <option value="today">Aujourd'hui</option>
                            <option value="yesterday">Hier</option>
                            <option value="week">Cette semaine</option>
                            <option value="month">Ce mois</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="logUserFilter">Utilisateur:</label>
                        <input type="text" id="logUserFilter" class="form-control" placeholder="Email utilisateur">
                    </div>
                    
                    <div class="filter-group">
                        <label for="logIPFilter">Adresse IP:</label>
                        <input type="text" id="logIPFilter" class="form-control" placeholder="Adresse IP">
                    </div>
                    
                    <button id="applyLogFilters" class="btn btn-primary">Appliquer</button>
                    <button id="resetLogFilters" class="btn btn-secondary">Réinitialiser</button>
                </div>
            </div>
            
            <div class="logs-table-container">
                <table class="logs-table" id="securityLogsTable">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Utilisateur</th>
                            <th>Adresse IP</th>
                            <th>Statut</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody id="securityLogsTableBody">
                        <tr>
                            <td colspan="5" class="no-data">Chargement des logs...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="logs-actions">
                <div class="form-group">
                    <label for="exportFormat">Format d'exportation:</label>
                    <select id="exportFormat" class="form-control">
                        <option value="json">JSON</option>
                        <option value="csv">CSV</option>
                        <option value="siem">SIEM</option>
                    </select>
                </div>
                
                <button id="exportLogs" class="btn btn-primary">Exporter les logs</button>
                <button id="clearLogs" class="btn btn-danger">Effacer tous les logs</button>
            </div>
        </div>
    `;
    
    // Ajouter la section au contenu de l'administration
    adminContent.appendChild(securitySection);
    
    // Initialiser les données du tableau de bord
    updateSecurityDashboard();
    
    // Ajouter les gestionnaires d'événements
    addSecurityDashboardEventListeners();
}

// Fonction pour mettre à jour le tableau de bord de sécurité
function updateSecurityDashboard() {
    // Mettre à jour les statistiques
    updateSecurityStats();
    
    // Mettre à jour les alertes récentes
    updateRecentAlerts();
    
    // Mettre à jour les logs de sécurité
    updateSecurityLogs();
}

// Fonction pour mettre à jour les statistiques de sécurité
function updateSecurityStats() {
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

// Fonction pour mettre à jour les alertes récentes
function updateRecentAlerts() {
    const alertsContainer = document.getElementById('recentAlertsContainer');
    if (!alertsContainer) return;
    
    // Obtenir les alertes actives
    let activeAlerts = [];
    
    if (window.securityAlertSystem && window.securityAlertSystem.getActiveAlerts) {
        activeAlerts = window.securityAlertSystem.getActiveAlerts();
    } else if (window.securityLogs && window.securityLogs.getActiveAlerts) {
        activeAlerts = window.securityLogs.getActiveAlerts();
    }
    
    // Afficher les alertes
    if (activeAlerts.length === 0) {
        alertsContainer.innerHTML = '<p class="no-data">Aucune alerte active</p>';
    } else {
        // Trier les alertes par date (les plus récentes en premier)
        const sortedAlerts = [...activeAlerts].sort((a, b) => 
            new Date(b.timestamp || b.createdAt) - new Date(a.timestamp || a.createdAt)
        );
        
        // Limiter à 5 alertes récentes
        const recentAlerts = sortedAlerts.slice(0, 5);
        
        // Générer le HTML pour les alertes
        alertsContainer.innerHTML = recentAlerts.map(alert => `
            <div class="alert-item ${alert.severity}">
                <div class="alert-header">
                    <span class="alert-severity">${alert.severity.toUpperCase()}</span>
                    <span class="alert-time">${new Date(alert.timestamp || alert.createdAt).toLocaleString()}</span>
                </div>
                <div class="alert-content">
                    <p>${alert.details || alert.reason}</p>
                    ${alert.ipAddress ? `<p>IP: ${alert.ipAddress}</p>` : ''}
                </div>
            </div>
        `).join('');
    }
}

// Fonction pour mettre à jour les logs de sécurité
function updateSecurityLogs() {
    console.log('Mise à jour des logs de sécurité...');
    const logsTableBody = document.getElementById('securityLogsTableBody');
    if (!logsTableBody) {
        console.warn('Élément securityLogsTableBody non trouvé dans le DOM');
        return;
    }
    
    if (!window.securityLogs) {
        console.warn('Module securityLogs non disponible');
        logsTableBody.innerHTML = '<tr><td colspan="5" class="no-data">Module de logs non initialisé</td></tr>';
        return;
    }
    
    // S'assurer que la fonction getAllLogs existe
    if (typeof window.securityLogs.getAllLogs !== 'function') {
        console.error('La fonction getAllLogs n\'est pas disponible dans le module securityLogs');
        logsTableBody.innerHTML = '<tr><td colspan="5" class="no-data">Erreur: fonction getAllLogs non disponible</td></tr>';
        return;
    }
    
    // S'assurer que les logs sont chargés depuis le localStorage
    if (typeof window.securityLogs.loadLogsFromStorage === 'function') {
        window.securityLogs.loadLogsFromStorage();
    }
    
    // Obtenir tous les logs
    const logs = window.securityLogs.getAllLogs();
    console.log('Nombre de logs récupérés:', logs.length);
    
    // Afficher les logs
    if (logs.length === 0) {
        logsTableBody.innerHTML = '<tr><td colspan="5" class="no-data">Aucun log disponible</td></tr>';
    } else {
        // Trier les logs par date (les plus récents en premier)
        const sortedLogs = [...logs].sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        
        // Limiter à 50 logs récents
        const recentLogs = sortedLogs.slice(0, 50);
        
        // Générer le HTML pour les logs
        logsTableBody.innerHTML = recentLogs.map(log => `
            <tr class="log-row ${log.status}">
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td>${log.email || 'N/A'}</td>
                <td>${log.ipAddress}</td>
                <td><span class="log-status ${log.status}">${log.status}</span></td>
                <td>${log.details}</td>
            </tr>
        `).join('');
    }
}

// Fonction pour ajouter les gestionnaires d'événements au tableau de bord de sécurité
function addSecurityDashboardEventListeners() {
    // Gestionnaire pour le bouton d'exportation des logs
    const exportLogsBtn = document.getElementById('exportLogs');
    if (exportLogsBtn && window.securityLogs) {
        exportLogsBtn.addEventListener('click', function() {
            const format = document.getElementById('exportFormat').value;
            window.securityLogs.downloadLogs(format);
        });
    }
    
    // Gestionnaire pour le bouton d'effacement des logs
    const clearLogsBtn = document.getElementById('clearLogs');
    if (clearLogsBtn && window.securityLogs) {
        clearLogsBtn.addEventListener('click', function() {
            if (confirm('Êtes-vous sûr de vouloir effacer tous les logs ? Cette action est irréversible.')) {
                window.securityLogs.clearAllLogs();
                updateSecurityDashboard();
            }
        });
    }
    
    // Gestionnaire pour le bouton d'application des filtres de logs
    const applyLogFiltersBtn = document.getElementById('applyLogFilters');
    if (applyLogFiltersBtn) {
        applyLogFiltersBtn.addEventListener('click', function() {
            filterSecurityLogs();
        });
    }
    
    // Gestionnaire pour le bouton de réinitialisation des filtres de logs
    const resetLogFiltersBtn = document.getElementById('resetLogFilters');
    if (resetLogFiltersBtn) {
        resetLogFiltersBtn.addEventListener('click', function() {
            document.getElementById('logTypeFilter').value = 'all';
            document.getElementById('logDateFilter').value = 'all';
            document.getElementById('logUserFilter').value = '';
            document.getElementById('logIPFilter').value = '';
            
            filterSecurityLogs();
        });
    }
    
    // Gestionnaire pour le bouton d'exportation des logs SIEM
    const exportSIEMLogsBtn = document.getElementById('exportSIEMLogs');
    if (exportSIEMLogsBtn && window.siemIntegration) {
        exportSIEMLogsBtn.addEventListener('click', function() {
            const siemType = document.getElementById('siemType').value;
            window.siemIntegration.downloadLogs(siemType);
        });
    }
    
    // Gestionnaire pour le bouton d'envoi des logs SIEM
    const sendSIEMLogsBtn = document.getElementById('sendSIEMLogs');
    if (sendSIEMLogsBtn && window.siemIntegration) {
        sendSIEMLogsBtn.addEventListener('click', function() {
            const siemType = document.getElementById('siemType').value;
            const result = window.siemIntegration.sendLogs(siemType);
            
            if (result.success) {
                alert(`${result.sent} logs envoyés avec succès à ${siemType.toUpperCase()}`);
            } else {
                alert(`Erreur lors de l'envoi des logs à ${siemType.toUpperCase()}`);
            }
        });
    }
    
    // Gestionnaire pour le bouton d'enregistrement de la configuration d'alerte
    const saveAlertConfigBtn = document.getElementById('saveAlertConfig');
    if (saveAlertConfigBtn) {
        saveAlertConfigBtn.addEventListener('click', function() {
            const failedLoginThreshold = parseInt(document.getElementById('failedLoginThreshold').value);
            const timeWindowMinutes = parseInt(document.getElementById('timeWindowMinutes').value);
            
            // Enregistrer la configuration
            if (window.securityAlertSystem) {
                // Dans un environnement réel, on mettrait à jour la configuration
                alert('Configuration enregistrée avec succès');
            } else {
                alert('Le système d\'alerte n\'est pas disponible');
            }
        });
    }
    
    // Gestionnaire pour le bouton de test d'alerte
    const testAlertBtn = document.getElementById('testAlert');
    if (testAlertBtn) {
        testAlertBtn.addEventListener('click', function() {
            // Créer une alerte de test
            if (window.securityAlertSystem && window.securityAlertSystem.createAlert) {
                window.securityAlertSystem.createAlert({
                    type: 'test_alert',
                    severity: 'medium',
                    ipAddress: '127.0.0.1',
                    email: 'test@example.com',
                    details: 'Ceci est une alerte de test',
                    timestamp: new Date().toISOString()
                });
                
                updateSecurityDashboard();
            } else if (window.securityLogs && window.securityLogs.createSecurityAlert) {
                window.securityLogs.createSecurityAlert(
                    '127.0.0.1',
                    'Ceci est une alerte de test',
                    window.securityLogs.LOG_TYPES.WARNING
                );
                
                updateSecurityDashboard();
            } else {
                alert('Le système d\'alerte n\'est pas disponible');
            }
        });
    }
}

// Fonction pour filtrer les logs de sécurité
function filterSecurityLogs() {
    if (!window.securityLogs) return;
    
    const logsTableBody = document.getElementById('securityLogsTableBody');
    if (!logsTableBody) return;
    
    // Obtenir les valeurs des filtres
    const typeFilter = document.getElementById('logTypeFilter').value;
    const dateFilter = document.getElementById('logDateFilter').value;
    const userFilter = document.getElementById('logUserFilter').value.toLowerCase();
    const ipFilter = document.getElementById('logIPFilter').value.toLowerCase();
    
    // Obtenir tous les logs
    const logs = window.securityLogs.getAllLogs();
    
    // Appliquer les filtres
    const filteredLogs = logs.filter(log => {
        // Filtre par type
        if (typeFilter !== 'all' && log.status !== typeFilter) {
            return false;
        }
        
        // Filtre par date
        if (dateFilter !== 'all') {
            const logDate = new Date(log.timestamp);
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
                    if (logDate < today) return false;
                    break;
                case 'yesterday':
                    if (logDate < yesterday || logDate >= today) return false;
                    break;
                case 'week':
                    if (logDate < weekAgo) return false;
                    break;
                case 'month':
                    if (logDate < monthAgo) return false;
                    break;
            }
        }
        
        // Filtre par utilisateur
        if (userFilter && (!log.email || !log.email.toLowerCase().includes(userFilter))) {
            return false;
        }
        
        // Filtre par IP
        if (ipFilter && (!log.ipAddress || !log.ipAddress.toLowerCase().includes(ipFilter))) {
            return false;
        }
        
        return true;
    });
    
    // Trier les logs par date (les plus récents en premier)
    const sortedLogs = [...filteredLogs].sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
    );
    
    // Afficher les logs filtrés
    if (sortedLogs.length === 0) {
        logsTableBody.innerHTML = '<tr><td colspan="5" class="no-data">Aucun log ne correspond aux critères</td></tr>';
    } else {
        // Limiter à 50 logs
        const limitedLogs = sortedLogs.slice(0, 50);
        
        // Générer le HTML pour les logs
        logsTableBody.innerHTML = limitedLogs.map(log => `
            <tr class="log-row ${log.status}">
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td>${log.email || 'N/A'}</td>
                <td>${log.ipAddress}</td>
                <td><span class="log-status ${log.status}">${log.status}</span></td>
                <td>${log.details}</td>
            </tr>
        `).join('');
    }
}

// Fonction pour configurer les gestionnaires d'événements pour les formulaires de connexion
function setupLoginFormHandlers() {
    // Trouver le formulaire de connexion
    const loginForm = document.querySelector('form[action*="login"]');
    
    if (loginForm) {
        console.log('Formulaire de connexion trouvé, configuration des gestionnaires d\'événements...');
        
        // Ajouter un gestionnaire d'événements pour la soumission du formulaire
        loginForm.addEventListener('submit', function(e) {
            // Ne pas empêcher la soumission du formulaire, juste enregistrer l'événement
            
            // Récupérer les valeurs du formulaire
            const emailInput = loginForm.querySelector('input[type="email"], input[name="email"]');
            const email = emailInput ? emailInput.value : 'unknown';
            
            // Obtenir l'adresse IP (dans un environnement réel, ce serait l'IP du client)
            const ipAddress = '127.0.0.1'; // Simulé pour la démonstration
            
            // Enregistrer la tentative de connexion
            if (window.securityLogs && window.securityLogs.addLoginLog) {
                // Le statut sera mis à jour après la vérification des identifiants
                // Pour cette démonstration, nous simulons une tentative réussie
                window.securityLogs.addLoginLog(
                    email,
                    ipAddress,
                    window.securityLogs.LOG_TYPES.SUCCESS,
                    'Tentative de connexion (simulation)'
                );
                
                console.log('Tentative de connexion enregistrée pour', email);
            }
        });
        
        console.log('Gestionnaires d\'événements configurés pour le formulaire de connexion');
    } else {
        console.log('Aucun formulaire de connexion trouvé sur cette page');
    }
}