// Configuration pour les outils d'audit de sécurité des dépendances
// Ce fichier contient les configurations pour OWASP Dependency-Check, Snyk et GitHub Dependabot

/**
 * Configuration pour l'audit de sécurité des dépendances
 */
window.securityAuditConfig = {
    // Version de la configuration
    version: '1.0.0',
    
    // Configuration OWASP Dependency-Check
    owaspDependencyCheck: {
        // Activer l'analyse OWASP Dependency-Check
        enabled: true,
        
        // Fréquence d'analyse (en jours)
        frequency: 7,
        
        // Niveau de sévérité minimum pour les alertes
        // (LOW, MEDIUM, HIGH, CRITICAL)
        minimumSeverity: 'MEDIUM',
        
        // Formats de rapport
        reportFormats: ['HTML', 'JSON'],
        
        // Chemin pour les rapports
        reportPath: './security-reports/dependency-check',
        
        // Commande d'exécution (pour référence)
        // Note: Cette commande doit être exécutée manuellement dans un terminal
        command: 'dependency-check --project "Tech Shield" --out ./security-reports/dependency-check --scan .'
    },
    
    // Configuration Snyk
    snyk: {
        // Activer l'analyse Snyk
        enabled: true,
        
        // Fréquence d'analyse (en jours)
        frequency: 7,
        
        // Niveau de sévérité minimum pour les alertes
        // (low, medium, high, critical)
        minimumSeverity: 'medium',
        
        // Ignorer certaines vulnérabilités (par ID)
        ignoreVulnerabilities: [],
        
        // Commande d'exécution (pour référence)
        // Note: Cette commande doit être exécutée manuellement dans un terminal après installation de Snyk
        command: 'snyk test --all-projects'
    },
    
    // Configuration GitHub Dependabot
    // Note: Cette configuration doit être placée dans .github/dependabot.yml
    dependabot: {
        // Activer Dependabot
        enabled: true,
        
        // Fréquence des mises à jour
        // (daily, weekly, monthly)
        frequency: 'weekly',
        
        // Packages à surveiller
        packageEcosystems: ['npm'],
        
        // Configuration de référence pour .github/dependabot.yml
        configExample: `
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    target-branch: "develop"
    labels:
      - "dependencies"
      - "security"
`
    },
    
    // Intégration avec le système de logs de sécurité
    logsIntegration: {
        // Activer l'intégration avec les logs
        enabled: true,
        
        // Journaliser les résultats d'analyse
        logResults: true,
        
        // Créer des alertes pour les vulnérabilités critiques
        createAlerts: true
    }
};

/**
 * Initialise le système d'audit de sécurité des dépendances
 */
function initSecurityAuditSystem() {
    console.log('Initialisation du système d\'audit de sécurité des dépendances...');
    
    // Vérifier si le module de logs est disponible
    if (window.securityLogs) {
        // Journaliser l'initialisation
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: 'Système d\'audit de sécurité des dépendances initialisé',
            source: 'security-audit-config'
        });
    }
    
    // Créer un élément dans l'interface d'administration si disponible
    addSecurityAuditTab();
}

/**
 * Ajoute un onglet pour l'audit de sécurité dans l'interface d'administration
 */
function addSecurityAuditTab() {
    // Vérifier si nous sommes sur la page d'administration
    const adminNav = document.querySelector('.admin-nav');
    if (!adminNav) return;
    
    // Vérifier si l'onglet existe déjà
    if (!adminNav.querySelector('[data-tab="security-audit"]')) {
        // Créer l'élément de navigation
        const auditNavItem = document.createElement('a');
        auditNavItem.href = '#';
        auditNavItem.setAttribute('data-tab', 'security-audit');
        auditNavItem.innerHTML = `
            <i class="fas fa-shield-alt"></i>
            <span>Audit de dépendances</span>
        `;
        
        // Ajouter l'élément à la navigation
        adminNav.appendChild(auditNavItem);
        
        // Ajouter le gestionnaire d'événements
        auditNavItem.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Masquer toutes les sections
            document.querySelectorAll('.admin-section').forEach(section => {
                section.style.display = 'none';
            });
            
            // Afficher la section d'audit
            const auditSection = document.getElementById('securityAuditDashboard');
            if (auditSection) {
                auditSection.style.display = 'block';
            } else {
                // Créer la section si elle n'existe pas
                createSecurityAuditDashboard();
            }
            
            // Mettre à jour la classe active
            document.querySelectorAll('.admin-nav a').forEach(link => {
                link.classList.remove('active');
            });
            this.classList.add('active');
        });
    }
}

/**
 * Crée le tableau de bord d'audit de sécurité
 */
function createSecurityAuditDashboard() {
    const adminContent = document.querySelector('.admin-content');
    if (!adminContent) return;
    
    // Créer la section d'audit
    const auditSection = document.createElement('div');
    auditSection.id = 'securityAuditDashboard';
    auditSection.className = 'admin-section';
    
    // Construire le contenu du tableau de bord
    auditSection.innerHTML = `
        <h2>Audit de sécurité des dépendances</h2>
        
        <div class="audit-dashboard-grid">
            <!-- Statistiques d'audit -->
            <div class="dashboard-card" id="auditStats">
                <h3>Statistiques</h3>
                <div class="stats-container">
                    <div class="stat-card">
                        <div class="stat-value" id="totalDependenciesCount">1</div>
                        <div class="stat-label">Dépendances totales</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-value" id="vulnerableDependenciesCount">0</div>
                        <div class="stat-label">Dépendances vulnérables</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-value" id="lastAuditDate">N/A</div>
                        <div class="stat-label">Dernier audit</div>
                    </div>
                </div>
            </div>
            
            <!-- Outils d'audit -->
            <div class="dashboard-card" id="auditTools">
                <h3>Outils d'audit</h3>
                <div class="tools-container">
                    <div class="tool-card">
                        <h4>OWASP Dependency-Check</h4>
                        <p>Analyse les dépendances pour identifier les vulnérabilités connues (CVE).</p>
                        <div class="tool-actions">
                            <button id="runOwaspCheck" class="btn btn-primary">Exécuter l'analyse</button>
                        </div>
                    </div>
                    
                    <div class="tool-card">
                        <h4>Snyk</h4>
                        <p>Détecte et corrige les vulnérabilités dans les dépendances.</p>
                        <div class="tool-actions">
                            <button id="runSnykCheck" class="btn btn-primary">Exécuter l'analyse</button>
                        </div>
                    </div>
                    
                    <div class="tool-card">
                        <h4>GitHub Dependabot</h4>
                        <p>Automatise les mises à jour de dépendances via des pull requests.</p>
                        <div class="tool-actions">
                            <button id="setupDependabot" class="btn btn-primary">Configurer Dependabot</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Dépendances actuelles -->
            <div class="dashboard-card" id="currentDependencies">
                <h3>Dépendances actuelles</h3>
                <div class="dependencies-container">
                    <table class="dependencies-table">
                        <thead>
                            <tr>
                                <th>Nom</th>
                                <th>Version actuelle</th>
                                <th>Dernière version</th>
                                <th>Statut</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>fullcalendar</td>
                                <td>6.1.10</td>
                                <td>6.1.10</td>
                                <td><span class="status-badge status-ok">À jour</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
    
    // Ajouter la section au contenu de l'administration
    adminContent.appendChild(auditSection);
    
    // Ajouter les gestionnaires d'événements
    document.getElementById('runOwaspCheck')?.addEventListener('click', function() {
        alert('Pour exécuter OWASP Dependency-Check, veuillez installer l\'outil et exécuter la commande suivante dans un terminal:\n\ndependency-check --project "Tech Shield" --out ./security-reports/dependency-check --scan .');
    });
    
    document.getElementById('runSnykCheck')?.addEventListener('click', function() {
        alert('Pour exécuter Snyk, veuillez installer l\'outil et exécuter la commande suivante dans un terminal:\n\nsnyk test --all-projects');
    });
    
    document.getElementById('setupDependabot')?.addEventListener('click', function() {
        alert('Pour configurer GitHub Dependabot, créez un fichier .github/dependabot.yml dans votre dépôt avec la configuration fournie dans la documentation.');
    });
}

// Initialiser le système d'audit de sécurité lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le système d'audit de sécurité
    initSecurityAuditSystem();
});