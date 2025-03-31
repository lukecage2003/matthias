// Module d'administration RGPD pour Tech Shield

document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si l'utilisateur est connecté et a les droits d'administrateur
    if (window.auth && !window.auth.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }
    
    if (window.auth && !window.auth.isAdmin()) {
        // Rediriger vers la page d'accueil si l'utilisateur n'est pas administrateur
        window.location.href = 'index.html';
        return;
    }
    
    // Initialiser les composants RGPD
    initRGPDComponents();
    
    // Charger les données
    loadDashboardData();
    loadDeletionRequests();
    loadAnonymizationSettings();
    loadCookieConsentStats();
    
    // Ajouter les gestionnaires d'événements

/**
 * Charge les statistiques de consentement aux cookies
 */
function loadCookieConsentStats() {
    // Dans un environnement réel, ces données proviendraient d'une base de données
    // Ici, nous simulons des statistiques pour la démonstration
    
    // Créer la section de statistiques si elle n'existe pas déjà
    let cookieStatsSection = document.getElementById('cookie-stats-section');
    
    if (!cookieStatsSection) {
        const mainContainer = document.querySelector('.rgpd-admin-container');
        
        if (mainContainer) {
            // Créer la section
            cookieStatsSection = document.createElement('div');
            cookieStatsSection.id = 'cookie-stats-section';
            cookieStatsSection.className = 'rgpd-admin-section';
            
            // Ajouter l'en-tête
            const header = document.createElement('div');
            header.className = 'rgpd-admin-header';
            header.innerHTML = `
                <h2>Statistiques de Consentement aux Cookies</h2>
                <button id="refresh-cookie-stats" class="btn-refresh">Actualiser</button>
            `;
            
            // Ajouter les statistiques
            const statsContainer = document.createElement('div');
            statsContainer.className = 'rgpd-stats';
            statsContainer.innerHTML = `
                <div class="stat-card">
                    <h3>Consentements Totaux</h3>
                    <div class="stat-value">1,245</div>
                    <div class="stat-trend">+12% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Taux d'Acceptation</h3>
                    <div class="stat-value">78%</div>
                    <div class="stat-trend">+3% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Cookies Fonctionnels</h3>
                    <div class="stat-value">68%</div>
                    <div class="stat-trend">+5% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Cookies d'Analyse</h3>
                    <div class="stat-value">54%</div>
                    <div class="stat-trend">+2% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Cookies Marketing</h3>
                    <div class="stat-value">42%</div>
                    <div class="stat-trend">-1% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Bannière Fermée Sans Action</h3>
                    <div class="stat-value">15%</div>
                    <div class="stat-trend">-2% ce mois</div>
                </div>
            `;
            
            // Ajouter le graphique
            const chartContainer = document.createElement('div');
            chartContainer.className = 'chart-container';
            chartContainer.innerHTML = `
                <h3>Évolution des Consentements</h3>
                <div class="chart-placeholder">
                    <div class="chart-bar" style="height: 60%;">Jan</div>
                    <div class="chart-bar" style="height: 65%;">Fév</div>
                    <div class="chart-bar" style="height: 70%;">Mar</div>
                    <div class="chart-bar" style="height: 68%;">Avr</div>
                    <div class="chart-bar" style="height: 72%;">Mai</div>
                    <div class="chart-bar" style="height: 75%;">Juin</div>
                    <div class="chart-bar" style="height: 78%;">Juil</div>
                    <div class="chart-bar" style="height: 80%;">Août</div>
                    <div class="chart-bar" style="height: 82%;">Sep</div>
                    <div class="chart-bar" style="height: 78%;">Oct</div>
                    <div class="chart-bar" style="height: 80%;">Nov</div>
                    <div class="chart-bar chart-bar-current" style="height: 85%;">Déc</div>
                </div>
            `;
            
            // Ajouter les paramètres de configuration
            const settingsContainer = document.createElement('div');
            settingsContainer.className = 'settings-container';
            settingsContainer.innerHTML = `
                <h3>Configuration de la Bannière de Cookies</h3>
                <div class="settings-list">
                    <div class="setting-item">
                        <div class="setting-label">Position de la bannière</div>
                        <div class="setting-control">
                            <select id="cookie-banner-position">
                                <option value="bottom" selected>Bas de page</option>
                                <option value="top">Haut de page</option>
                            </select>
                        </div>
                    </div>
                    <div class="setting-item">
                        <div class="setting-label">Thème de la bannière</div>
                        <div class="setting-control">
                            <select id="cookie-banner-theme">
                                <option value="dark" selected>Sombre</option>
                                <option value="light">Clair</option>
                            </select>
                        </div>
                    </div>
                    <div class="setting-item">
                        <div class="setting-label">Durée de validité du consentement</div>
                        <div class="setting-control">
                            <select id="cookie-expiration">
                                <option value="30">30 jours</option>
                                <option value="90">90 jours</option>
                                <option value="180" selected>180 jours</option>
                                <option value="365">365 jours</option>
                            </select>
                        </div>
                    </div>
                    <div class="setting-item">
                        <div class="setting-label">Afficher la bannière à chaque visite</div>
                        <div class="setting-control">
                            <select id="cookie-show-each-visit">
                                <option value="false" selected>Non</option>
                                <option value="true">Oui</option>
                            </select>
                        </div>
                    </div>
                </div>
                <button id="save-cookie-settings" class="btn-save">Enregistrer les paramètres</button>
            `;
            
            // Assembler la section
            cookieStatsSection.appendChild(header);
            cookieStatsSection.appendChild(statsContainer);
            cookieStatsSection.appendChild(chartContainer);
            cookieStatsSection.appendChild(settingsContainer);
            
            // Ajouter la section au conteneur principal
            // Trouver la position appropriée (après la section des demandes de suppression)
            const deletionRequestsSection = document.querySelector('.rgpd-admin-section');
            if (deletionRequestsSection && deletionRequestsSection.nextSibling) {
                mainContainer.insertBefore(cookieStatsSection, deletionRequestsSection.nextSibling);
            } else {
                mainContainer.appendChild(cookieStatsSection);
            }
            
            // Ajouter les gestionnaires d'événements
            document.getElementById('refresh-cookie-stats').addEventListener('click', function() {
                // Simuler une actualisation des données
                alert('Statistiques actualisées');
            });
            
            document.getElementById('save-cookie-settings').addEventListener('click', function() {
                // Récupérer les valeurs
                const position = document.getElementById('cookie-banner-position').value;
                const theme = document.getElementById('cookie-banner-theme').value;
                const expiration = document.getElementById('cookie-expiration').value;
                const showEachVisit = document.getElementById('cookie-show-each-visit').value === 'true';
                
                // Simuler l'enregistrement des paramètres
                alert('Paramètres de la bannière de cookies enregistrés');
                
                // Dans un environnement réel, ces paramètres seraient enregistrés dans une base de données
                // et appliqués à la configuration du module de gestion des cookies
            });
        }
    }
}
    setupEventListeners();
});

/**
 * Initialise les composants RGPD
 */
function initRGPDComponents() {
    // Initialiser la configuration RGPD si disponible
    if (window.rgpdConfig && window.rgpdConfig.init) {
        window.rgpdConfig.init();
    }
    
    // Initialiser le module d'anonymisation si disponible
    if (window.dataAnonymizer && window.dataAnonymizer.init) {
        window.dataAnonymizer.init();
    }
}

/**
 * Configure les écouteurs d'événements
 */
function setupEventListeners() {
    // Gestionnaire pour les onglets
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            // Retirer la classe active de tous les onglets
            tabs.forEach(t => t.classList.remove('active'));
            // Ajouter la classe active à l'onglet cliqué
            this.classList.add('active');
            
            // Masquer tous les contenus d'onglet
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Afficher le contenu de l'onglet sélectionné
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId + '-tab').classList.add('active');
            
            // Recharger les données si nécessaire
            if (tabId === 'requests') {
                loadDeletionRequests();
            } else if (tabId === 'dashboard') {
                loadDashboardData();
            }
        });
    });
    
    // Gestionnaire pour les filtres de demandes
    const statusFilter = document.getElementById('status-filter');
    const dateFilter = document.getElementById('date-filter');
    const typeFilter = document.getElementById('type-filter');
    
    if (statusFilter) statusFilter.addEventListener('change', loadDeletionRequests);
    if (dateFilter) dateFilter.addEventListener('change', loadDeletionRequests);
    if (typeFilter) typeFilter.addEventListener('change', loadDeletionRequests);
    
    // Gestionnaire pour l'enregistrement des paramètres d'anonymisation
    const saveSettingsBtn = document.getElementById('save-anonymization-settings');
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', saveAnonymizationSettings);
    }
    
    // Gestionnaire pour l'exécution d'un audit
    const runAuditBtn = document.getElementById('run-audit');
    if (runAuditBtn) {
        runAuditBtn.addEventListener('click', runRGPDAudit);
    }
    
    // Gestionnaire pour l'exportation du rapport
    const exportReportBtn = document.getElementById('btn-export-report');
    if (exportReportBtn) {
        exportReportBtn.addEventListener('click', exportRGPDReport);
    }
    
    // Ajouter des gestionnaires d'événements pour les boutons d'action des demandes
    // Ces gestionnaires seront ajoutés dynamiquement lors du chargement des demandes
}

/**
 * Charge les données du tableau de bord
 */
function loadDashboardData() {
    // Récupérer les demandes de suppression
    const deletionRequests = getDeletionRequests();
    
    // Mettre à jour les compteurs
    updateRequestsCounters(deletionRequests);
    
    // Charger l'activité récente
    loadRecentActivity();
}

/**
 * Met à jour les compteurs de demandes
 * @param {Array} requests - Les demandes de suppression
 */
function updateRequestsCounters(requests) {
    // Compter les demandes par statut
    const pendingCount = requests.filter(req => req.status === 'pending').length;
    const completedCount = requests.filter(req => req.status === 'completed').length;
    
    // Calculer le temps moyen de traitement
    let totalProcessingTime = 0;
    let processedRequestsCount = 0;
    
    requests.forEach(req => {
        if (req.status === 'completed' && req.requestDate && req.processedDate) {
            const requestDate = new Date(req.requestDate);
            const processedDate = new Date(req.processedDate);
            const processingTime = Math.floor((processedDate - requestDate) / (1000 * 60 * 60 * 24)); // en jours
            totalProcessingTime += processingTime;
            processedRequestsCount++;
        }
    });
    
    const avgProcessingTime = processedRequestsCount > 0 ? Math.round(totalProcessingTime / processedRequestsCount) : 0;
    
    // Mettre à jour les éléments HTML
    const pendingCountElement = document.getElementById('pending-requests-count');
    const completedCountElement = document.getElementById('completed-requests-count');
    const avgProcessingTimeElement = document.getElementById('avg-processing-time');
    const anonymizedDataCountElement = document.getElementById('anonymized-data-count');
    
    if (pendingCountElement) pendingCountElement.textContent = pendingCount;
    if (completedCountElement) completedCountElement.textContent = completedCount;
    if (avgProcessingTimeElement) avgProcessingTimeElement.textContent = avgProcessingTime + ' jours';
    
    // Simuler un compteur de données anonymisées
    // Dans un environnement de production, cette valeur serait calculée à partir des données réelles
    if (anonymizedDataCountElement) {
        const anonymizedCount = completedCount * 5; // Estimation simple: 5 éléments de données par demande
        anonymizedDataCountElement.textContent = anonymizedCount;
    }
}

/**
 * Charge l'activité récente
 */
function loadRecentActivity() {
    const activityTable = document.getElementById('recent-activity-table');
    if (!activityTable) return;
    
    const tbody = activityTable.querySelector('tbody');
    if (!tbody) return;
    
    // Simuler des données d'activité récente
    // Dans un environnement de production, ces données proviendraient d'une base de données
    const recentActivities = [
        {
            date: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 heures avant
            type: 'Demande',
            description: 'Nouvelle demande de suppression reçue',
            user: 'j***@example.com'
        },
        {
            date: new Date(Date.now() - 5 * 60 * 60 * 1000), // 5 heures avant
            type: 'Traitement',
            description: 'Demande de suppression traitée',
            user: 'admin@techshield.com'
        },
        {
            date: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // 1 jour avant
            type: 'Anonymisation',
            description: 'Logs de sécurité anonymisés',
            user: 'admin@techshield.com'
        },
        {
            date: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 jours avant
            type: 'Audit',
            description: 'Audit de conformité RGPD effectué',
            user: 'admin@techshield.com'
        }
    ];
    
    // Vider le tableau
    tbody.innerHTML = '';
    
    // Ajouter les activités au tableau
    recentActivities.forEach(activity => {
        const row = document.createElement('tr');
        
        // Formater la date
        const formattedDate = activity.date.toLocaleDateString() + ' ' + activity.date.toLocaleTimeString();
        
        row.innerHTML = `
            <td>${formattedDate}</td>
            <td>${activity.type}</td>
            <td>${activity.description}</td>
            <td>${activity.user}</td>
        `;
        
        tbody.appendChild(row);
    });
}

/**
 * Récupère les demandes de suppression
 * @returns {Array} - Les demandes de suppression
 */
function getDeletionRequests() {
    // Récupérer les demandes depuis le stockage local
    const storedRequests = localStorage.getItem('deletionRequests');
    
    if (storedRequests) {
        try {
            return JSON.parse(storedRequests);
        } catch (error) {
            console.error('Erreur lors de la récupération des demandes:', error);
        }
    }
    
    return [];
}

/**
 * Charge les demandes de suppression dans le tableau
 */
function loadDeletionRequests() {
    const requestsTable = document.getElementById('deletion-requests-table');
    if (!requestsTable) return;
    
    const tbody = requestsTable.querySelector('tbody');
    if (!tbody) return;
    
    // Récupérer les demandes
    let requests = getDeletionRequests();
    
    // Appliquer les filtres
    requests = filterRequests(requests);
    
    // Vider le tableau
    tbody.innerHTML = '';
    
    // Ajouter les demandes au tableau
    requests.forEach(request => {
        const row = document.createElement('tr');
        
        // Formater la date
        const requestDate = new Date(request.requestDate);
        const formattedDate = requestDate.toLocaleDateString();
        
        // Déterminer la classe de statut
        const statusClass = 'status-' + request.status;
        
        // Créer les boutons d'action en fonction du statut
        let actionButtons = '';
        
        if (request.status === 'pending') {
            actionButtons = `
                <button class="btn-action btn-process" data-id="${request.requestId}">Traiter</button>
                <button class="btn-action btn-reject" data-id="${request.requestId}">Rejeter</button>
            `;
        } else {
            actionButtons = `
                <button class="btn-action btn-view" data-id="${request.requestId}">Détails</button>
            `;
        }
        
        row.innerHTML = `
            <td>${request.requestId}</td>
            <td>${formattedDate}</td>
            <td>${request.email}</td>
            <td>${request.type}</td>
            <td><span class="status-badge ${statusClass}">${getStatusLabel(request.status)}</span></td>
            <td class="action-buttons">${actionButtons}</td>
        `;
        
        tbody.appendChild(row);
    });
    
    // Ajouter les gestionnaires d'événements

/**
 * Charge les statistiques de consentement aux cookies
 */
function loadCookieConsentStats() {
    // Dans un environnement réel, ces données proviendraient d'une base de données
    // Ici, nous simulons des statistiques pour la démonstration
    
    // Créer la section de statistiques si elle n'existe pas déjà
    let cookieStatsSection = document.getElementById('cookie-stats-section');
    
    if (!cookieStatsSection) {
        const mainContainer = document.querySelector('.rgpd-admin-container');
        
        if (mainContainer) {
            // Créer la section
            cookieStatsSection = document.createElement('div');
            cookieStatsSection.id = 'cookie-stats-section';
            cookieStatsSection.className = 'rgpd-admin-section';
            
            // Ajouter l'en-tête
            const header = document.createElement('div');
            header.className = 'rgpd-admin-header';
            header.innerHTML = `
                <h2>Statistiques de Consentement aux Cookies</h2>
                <button id="refresh-cookie-stats" class="btn-refresh">Actualiser</button>
            `;
            
            // Ajouter les statistiques
            const statsContainer = document.createElement('div');
            statsContainer.className = 'rgpd-stats';
            statsContainer.innerHTML = `
                <div class="stat-card">
                    <h3>Consentements Totaux</h3>
                    <div class="stat-value">1,245</div>
                    <div class="stat-trend">+12% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Taux d'Acceptation</h3>
                    <div class="stat-value">78%</div>
                    <div class="stat-trend">+3% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Cookies Fonctionnels</h3>
                    <div class="stat-value">68%</div>
                    <div class="stat-trend">+5% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Cookies d'Analyse</h3>
                    <div class="stat-value">54%</div>
                    <div class="stat-trend">+2% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Cookies Marketing</h3>
                    <div class="stat-value">42%</div>
                    <div class="stat-trend">-1% ce mois</div>
                </div>
                <div class="stat-card">
                    <h3>Bannière Fermée Sans Action</h3>
                    <div class="stat-value">15%</div>
                    <div class="stat-trend">-2% ce mois</div>
                </div>
            `;
            
            // Ajouter le graphique
            const chartContainer = document.createElement('div');
            chartContainer.className = 'chart-container';
            chartContainer.innerHTML = `
                <h3>Évolution des Consentements</h3>
                <div class="chart-placeholder">
                    <div class="chart-bar" style="height: 60%;">Jan</div>
                    <div class="chart-bar" style="height: 65%;">Fév</div>
                    <div class="chart-bar" style="height: 70%;">Mar</div>
                    <div class="chart-bar" style="height: 68%;">Avr</div>
                    <div class="chart-bar" style="height: 72%;">Mai</div>
                    <div class="chart-bar" style="height: 75%;">Juin</div>
                    <div class="chart-bar" style="height: 78%;">Juil</div>
                    <div class="chart-bar" style="height: 80%;">Août</div>
                    <div class="chart-bar" style="height: 82%;">Sep</div>
                    <div class="chart-bar" style="height: 78%;">Oct</div>
                    <div class="chart-bar" style="height: 80%;">Nov</div>
                    <div class="chart-bar chart-bar-current" style="height: 85%;">Déc</div>
                </div>
            `;
            
            // Ajouter les paramètres de configuration
            const settingsContainer = document.createElement('div');
            settingsContainer.className = 'settings-container';
            settingsContainer.innerHTML = `
                <h3>Configuration de la Bannière de Cookies</h3>
                <div class="settings-list">
                    <div class="setting-item">
                        <div class="setting-label">Position de la bannière</div>
                        <div class="setting-control">
                            <select id="cookie-banner-position">
                                <option value="bottom" selected>Bas de page</option>
                                <option value="top">Haut de page</option>
                            </select>
                        </div>
                    </div>
                    <div class="setting-item">
                        <div class="setting-label">Thème de la bannière</div>
                        <div class="setting-control">
                            <select id="cookie-banner-theme">
                                <option value="dark" selected>Sombre</option>
                                <option value="light">Clair</option>
                            </select>
                        </div>
                    </div>
                    <div class="setting-item">
                        <div class="setting-label">Durée de validité du consentement</div>
                        <div class="setting-control">
                            <select id="cookie-expiration">
                                <option value="30">30 jours</option>
                                <option value="90">90 jours</option>
                                <option value="180" selected>180 jours</option>
                                <option value="365">365 jours</option>
                            </select>
                        </div>
                    </div>
                    <div class="setting-item">
                        <div class="setting-label">Afficher la bannière à chaque visite</div>
                        <div class="setting-control">
                            <select id="cookie-show-each-visit">
                                <option value="false" selected>Non</option>
                                <option value="true">Oui</option>
                            </select>
                        </div>
                    </div>
                </div>
                <button id="save-cookie-settings" class="btn-save">Enregistrer les paramètres</button>
            `;
            
            // Assembler la section
            cookieStatsSection.appendChild(header);
            cookieStatsSection.appendChild(statsContainer);
            cookieStatsSection.appendChild(chartContainer);
            cookieStatsSection.appendChild(settingsContainer);
            
            // Ajouter la section au conteneur principal
            // Trouver la position appropriée (après la section des demandes de suppression)
            const deletionRequestsSection = document.querySelector('.rgpd-admin-section');
            if (deletionRequestsSection && deletionRequestsSection.nextSibling) {
                mainContainer.insertBefore(cookieStatsSection, deletionRequestsSection.nextSibling);
            } else {
                mainContainer.appendChild(cookieStatsSection);
            }
            
            // Ajouter les gestionnaires d'événements
            document.getElementById('refresh-cookie-stats').addEventListener('click', function() {
                // Simuler une actualisation des données
                alert('Statistiques actualisées');
            });
            
            document.getElementById('save-cookie-settings').addEventListener('click', function() {
                // Récupérer les valeurs
                const position = document.getElementById('cookie-banner-position').value;
                const theme = document.getElementById('cookie-banner-theme').value;
                const expiration = document.getElementById('cookie-expiration').value;
                const showEachVisit = document.getElementById('cookie-show-each-visit').value === 'true';
                
                // Simuler l'enregistrement des paramètres
                alert('Paramètres de la bannière de cookies enregistrés');
                
                // Dans un environnement réel, ces paramètres seraient enregistrés dans une base de données
                // et appliqués à la configuration du module de gestion des cookies
            });
        }
    }
} pour les boutons d'action
    addActionButtonsEventListeners();
}

/**
 * Filtre les demandes en fonction des critères sélectionnés
 * @param {Array} requests - Les demandes à filtrer
 * @returns {Array} - Les demandes filtrées
 */
function filterRequests(requests) {
    const statusFilter = document.getElementById('status-filter');
    const dateFilter = document.getElementById('date-filter');
    const typeFilter = document.getElementById('type-filter');
    
    let filteredRequests = [...requests];
    
    // Filtrer par statut
    if (statusFilter && statusFilter.value !== 'all') {
        filteredRequests = filteredRequests.filter(req => req.status === statusFilter.value);
    }
    
    // Filtrer par date
    if (dateFilter && dateFilter.value) {
        const filterDate = new Date(dateFilter.value);
        filterDate.setHours(0, 0, 0, 0); // Début de la journée
        
        filteredRequests = filteredRequests.filter(req => {
            const requestDate = new Date(req.requestDate);
            requestDate.setHours(0, 0, 0, 0); // Début de la journée
            return requestDate.getTime() === filterDate.getTime();
        });
    }
    
    // Filtrer par type
    if (typeFilter && typeFilter.value !== 'all') {
        filteredRequests = filteredRequests.filter(req => req.type === typeFilter.value);
    }
    
    return filteredRequests;
}

/**
 * Ajoute les gestionnaires d'événements pour les boutons d'action
 */
function addActionButtonsEventListeners() {
    // Boutons de traitement
    const processButtons = document.querySelectorAll('.btn-process');
    processButtons.forEach(button => {
        button.addEventListener('click', function() {
            const requestId = this.getAttribute('data-id');
            processRequest(requestId);
        });
    });
    
    // Boutons de rejet
    const rejectButtons = document.querySelectorAll('.btn-reject');
    rejectButtons.forEach(button => {
        button.addEventListener('click', function() {
            const requestId = this.getAttribute('data-id');
            rejectRequest(requestId);
        });
    });
    
    // Boutons de détails
    const viewButtons = document.querySelectorAll('.btn-view');
    viewButtons.forEach(button => {
        button.addEventListener('click', function() {
            const requestId = this.getAttribute('data-id');
            viewRequestDetails(requestId);
        });
    });
}

/**
 * Traite une demande de suppression
 * @param {string} requestId - L'identifiant de la demande
 */
function processRequest(requestId) {
    // Récupérer les demandes
    const requests = getDeletionRequests();
    
    // Trouver la demande correspondante
    const requestIndex = requests.findIndex(req => req.requestId === requestId);
    if (requestIndex === -1) return;
    
    const request = requests[requestIndex];
    
    // Mettre à jour le statut de la demande
    request.status = 'processing';
    requests[requestIndex] = request;
    
    // Enregistrer les demandes mises à jour
    localStorage.setItem('deletionRequests', JSON.stringify(requests));
    
    // Simuler le traitement de la demande
    setTimeout(() => {
        // Récupérer à nouveau les demandes (elles peuvent avoir changé)
        const updatedRequests = getDeletionRequests();
        
        // Trouver la demande correspondante
        const updatedRequestIndex = updatedRequests.findIndex(req => req.requestId === requestId);
        if (updatedRequestIndex === -1) return;
        
        const updatedRequest = updatedRequests[updatedRequestIndex];
        
        // Mettre à jour le statut de la demande
        updatedRequest.status = 'completed';
        updatedRequest.processedDate = new Date().toISOString();
        updatedRequests[updatedRequestIndex] = updatedRequest;
        
        // Enregistrer les demandes mises à jour
        localStorage.setItem('deletionRequests', JSON.stringify(updatedRequests));
        
        // Recharger les demandes
        loadDeletionRequests();
        
        // Mettre à jour le tableau de bord
        loadDashboardData();
        
        // Afficher une notification
        alert(`La demande ${requestId} a été traitée avec succès.`);
    }, 1000); // Simuler un délai de traitement
    
    // Recharger les demandes pour afficher le statut "En cours"
    loadDeletionRequests();
}

/**
 * Rejette une demande de suppression
 * @param {string} requestId - L'identifiant de la demande
 */
function rejectRequest(requestId) {
    // Demander une confirmation
    if (!confirm('Êtes-vous sûr de vouloir rejeter cette demande ?')) {
        return;
    }
    
    // Récupérer les demandes
    const requests = getDeletionRequests();
    
    // Trouver la demande correspondante
    const requestIndex = requests.findIndex(req => req.requestId === requestId);
    if (requestIndex === -1) return;
    
    // Mettre à jour le statut de la demande
    requests[requestIndex].status = 'rejected';
    requests[requestIndex].processedDate = new Date().toISOString();
    
    // Enregistrer les demandes mises à jour
    localStorage.setItem('deletionRequests', JSON.stringify(requests));
    
    // Recharger les demandes
    loadDeletionRequests();
    
    // Mettre à jour le tableau de bord
    loadDashboardData();
    
    // Afficher une notification
    alert(`La demande ${requestId} a été rejetée.`);
}

/**
 * Affiche les détails d'une demande
 * @param {string} requestId - L'identifiant de la demande
 */
function viewRequestDetails(requestId) {
    // Récupérer les demandes
    const requests = getDeletionRequests();
    
    // Trouver la demande correspondante
    const request = requests.find(req => req.requestId === requestId);
    if (!request) return;
    
    // Afficher les détails dans une alerte (dans un environnement de production, utiliser une modale)
    const details = `
        ID: ${request.requestId}
        Email: ${request.email}
        Type: ${request.type}
        Date de demande: ${new Date(request.requestDate).toLocaleString()}
        Statut: ${getStatusLabel(request.status)}
        ${request.processedDate ? 'Date de traitement: ' + new Date(request.processedDate).toLocaleString() : ''}
        ${request.reason ? 'Motif: ' + request.reason : ''}
    `;
    
    alert(details);
}

/**
 * Retourne le libellé d'un statut
 * @param {string} status - Le statut
 * @returns {string} - Le libellé du statut
 */
function getStatusLabel(status) {
    switch (status) {
        case 'pending':
            return 'En attente';
        case 'processing':
            return 'En cours';
        case 'completed':
            return 'Terminé';
        case 'rejected':
            return 'Rejeté';
        default:
            return status;
    }
}

/**
 * Charge les paramètres d'anonymisation
 */
function loadAnonymizationSettings() {
    // Vérifier si la configuration RGPD est disponible
    if (!window.rgpdConfig || !window.rgpdConfig.config) return;
    
    const config = window.rgpdConfig.config;
    
    // Charger les paramètres pour les logs
    if (config.anonymization.logs) {
        const emailMethod = document.getElementById('logs-email-method');
        const ipMethod = document.getElementById('logs-ip-method');
        const userAgentMethod = document.getElementById('logs-useragent-method');
        
        if (emailMethod && config.anonymization.logs.email) {
            emailMethod.value = config.anonymization.logs.email.method;
        }
        
        if (ipMethod && config.anonymization.logs.ipAddress) {
            ipMethod.value = config.anonymization.logs.ipAddress.method;
        }
        
        if (userAgentMethod && config.anonymization.logs.userAgent) {
            userAgentMethod.value = config.anonymization.logs.userAgent.method;
        }
    }
    
    // Charger les paramètres pour les messages
    if (config.anonymization.messages) {
        const emailMethod = document.getElementById('messages-email-method');
        const contentMethod = document.getElementById('messages-content-method');
        
        if (emailMethod && config.anonymization.messages.email) {
            emailMethod.value = config.anonymization.messages.email.method;
        }
        
        if (contentMethod && config.anonymization.messages.content) {
            contentMethod.value = config.anonymization.messages.content.method;
        }
    }
    
    // Charger les paramètres pour les utilisateurs
    if (config.anonymization.users) {
        const emailMethod = document.getElementById('users-email-method');
        const nameMethod = document.getElementById('users-name-method');
        
        if (emailMethod && config.anonymization.users.email) {
            emailMethod.value = config.anonymization.users.email.method;
        }
        
        if (nameMethod && config.anonymization.users.name) {
            nameMethod.value = config.anonymization.users.name.method;
        }
    }
}

/**
 * Enregistre les paramètres d'anonymisation
 */
function saveAnonymizationSettings() {
    // Vérifier si la configuration RGPD est disponible
    if (!window.rgpdConfig || !window.rgpdConfig.config) {
        alert('La configuration RGPD n\'est pas disponible.');
        return;
    }
    
    const config = window.rgpdConfig.config;
    
    // Récupérer les paramètres pour les logs
    const logsEmailMethod = document.getElementById('logs-email-method');
    const logsIpMethod = document.getElementById('logs-ip-method');
    const logsUserAgentMethod = document.getElementById('logs-useragent-method');
    
    if (logsEmailMethod && logsIpMethod && logsUserAgentMethod) {
        config.anonymization.logs = {
            email: { type: 'email', method: logsEmailMethod.value },
            ipAddress: { type: 'ip', method: logsIpMethod.value },
            userAgent: { type: 'id', method: logsUserAgentMethod.value }
        };
    }
    
    // Récupérer les paramètres pour les messages
    const messagesEmailMethod = document.getElementById('messages-email-method');
    const messagesContentMethod = document.getElementById('messages-content-method');
    
    if (messagesEmailMethod && messagesContentMethod) {
        config.anonymization.messages = {
            email: { type: 'email', method: messagesEmailMethod.value },
            content: { type: 'id', method: messagesContentMethod.value }
        };
    }
    
    // Récupérer les paramètres pour les utilisateurs
    const usersEmailMethod = document.getElementById('users-email-method');
    const usersNameMethod = document.getElementById('users-name-method');
    
    if (usersEmailMethod && usersNameMethod) {
        config.anonymization.users = {
            email: { type: 'email', method: usersEmailMethod.value },
            name: { type: 'name', method: usersNameMethod.value }
        };
    }
    
    // Enregistrer la configuration
    // Dans un environnement de production, cette configuration serait enregistrée côté serveur
    localStorage.setItem('rgpdConfig', JSON.stringify(config));
    
    // Afficher une notification
    alert('Les paramètres d\'anonymisation ont été enregistrés.');
}

/**
 * Exécute un audit de conformité RGPD
 */
function runRGPDAudit() {
    const auditResultsElement = document.getElementById('audit-results');
    const lastAuditDateElement = document.getElementById('last-audit-date');
    
    if (!auditResultsElement) return;
    
    // Afficher un message de chargement
    auditResultsElement.innerHTML = '<p>Audit en cours...</p>';
    
    // Simuler un délai d'audit
    setTimeout(() => {
        // Générer les résultats de l'audit
        const auditResults = generateAuditResults();
        
        // Mettre à jour la date du dernier audit
        const now = new Date();
        if (lastAuditDateElement) {
            lastAuditDateElement.textContent = now.toLocaleDateString() + ' ' + now.toLocaleTimeString();
        }
        
        // Enregistrer la date du dernier audit
        localStorage.setItem('lastRGPDAudit', now.toISOString());
        
        // Afficher les résultats
        displayAuditResults(auditResults);
    }, 2000); // Simuler un délai d'audit
}

/**
 * Génère les résultats d'un audit de conformité RGPD
 * @returns {Object} - Les résultats de l'audit
 */
function generateAuditResults() {
    // Dans un environnement de production, cette fonction effectuerait un véritable audit
    // Pour cette démonstration, nous générons des résultats simulés
    
    return {
        score: 85, // Score de conformité sur 100
        date: new Date().toISOString(),
        categories: [
            {
                name: 'Collecte de données',
                score: 90,
                items: [
                    { name: 'Consentement explicite', status: 'success', details: 'Le consentement est correctement recueilli' },
                    { name: 'Finalités clairement définies', status: 'success', details: 'Les finalités sont clairement indiquées' },
                    { name: 'Minimisation des données', status: 'warning', details: 'Certaines données non essentielles sont collectées' }
                ]
            },
            {
                name: 'Droits des utilisateurs',
                score: 80,
                items: [
                    { name: 'Droit d\'accès', status: 'success', details: 'Les utilisateurs peuvent accéder à leurs données' },
                    { name: 'Droit à l\'effacement', status: 'success', details: 'Les utilisateurs peuvent demander la suppression de leurs données' },
                    { name: 'Droit à la portabilité', status: 'error', details: 'Fonctionnalité non implémentée' }
                ]
            },
            {
                name: 'Sécurité des données',
                score: 85,
                items: [
                    { name: 'Chiffrement', status: 'success', details: 'Les données sensibles sont chiffrées' },
                    { name: 'Anonymisation', status: 'success', details: 'Les données sont correctement anonymisées' },
                    { name: 'Contrôle d\'accès', status: 'warning', details: 'Certains contrôles d\'accès pourraient être renforcés' }
                ]
            }
        ],
        recommendations: [
            'Implémenter le droit à la portabilité des données',
            'Renforcer les contrôles d\'accès aux données sensibles',
            'Réduire la collecte de données non essentielles'
        ]
    };
}

/**
 * Affiche les résultats d'un audit
 * @param {Object} results - Les résultats de l'audit
 */
function displayAuditResults(results) {
    const auditResultsElement = document.getElementById('audit-results');
    if (!auditResultsElement) return;
    
    // Construire le HTML des résultats
    let html = `
        <div class="audit-summary">
            <h3>Score de conformité: ${results.score}/100</h3>
            <p>Date de l'audit: ${new Date(results.date).toLocaleString()}</p>
        </div>
    `;
    
    // Ajouter les catégories
    html += '<div class="audit-categories">';
    
    results.categories.forEach(category => {
        html += `
            <div class="audit-category">
                <h3>${category.name} (${category.score}/100)</h3>
                <ul>
        `;
        
        category.items.forEach(item => {
            html += `
                <li class="audit-item ${item.status}">
                    <strong>${item.name}:</strong> ${item.details}
                </li