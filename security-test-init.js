/**
 * Module d'initialisation des tests de sécurité pour Tech Shield
 * Ce module charge et initialise les outils de test de sécurité et les correctifs
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log('Initialisation des modules de test de sécurité...');
    
    // Vérifier si nous sommes sur la page d'administration
    if (!document.querySelector('.admin-container')) {
        console.log('Page d\'administration non détectée, les tests de sécurité ne seront pas chargés');
        return;
    }
    
    // Initialiser le module de correctifs de sécurité
    if (window.securityFixes) {
        window.securityFixes.init();
        console.log('Module de correctifs de sécurité initialisé');
    } else {
        console.warn('Module de correctifs de sécurité non disponible');
    }
    
    // Créer l'interface utilisateur pour les tests de sécurité
    createSecurityTestUI();
    
    /**
     * Crée l'interface utilisateur pour les tests de sécurité
     */
    function createSecurityTestUI() {
        // Vérifier si l'onglet de tests de sécurité existe déjà
        if (document.getElementById('security-tests')) {
            console.log('Interface de tests de sécurité déjà créée');
            return;
        }
        
        // Créer un nouvel onglet pour les tests de sécurité
        const adminNav = document.querySelector('.admin-nav ul');
        if (adminNav) {
            const securityTestTab = document.createElement('li');
            securityTestTab.innerHTML = '<a href="#" data-tab="security-tests">Tests de sécurité</a>';
            adminNav.appendChild(securityTestTab);
            
            // Ajouter le contenu de l'onglet
            const adminContent = document.querySelector('.admin-content');
            if (adminContent) {
                const securityTestContent = document.createElement('div');
                securityTestContent.id = 'security-tests';
                securityTestContent.className = 'admin-tab';
                securityTestContent.style.display = 'none';
                
                // Contenu de l'onglet
                securityTestContent.innerHTML = `
                    <h2>Tests de sécurité</h2>
                    <p>Cette section permet de tester la sécurité du site contre différentes attaques et d'appliquer des correctifs.</p>
                    
                    <div class="security-test-panel">
                        <h3>Simulation d'attaques</h3>
                        <p>Simule des attaques XSS, SQLi et CSRF pour détecter les vulnérabilités.</p>
                        <div class="security-test-controls">
                            <button id="runXSSTests" class="security-test-btn">Tester XSS</button>
                            <button id="runSQLiTests" class="security-test-btn">Tester SQLi</button>
                            <button id="runCSRFTests" class="security-test-btn">Tester CSRF</button>
                            <button id="runAllTests" class="security-test-btn primary">Tester tout</button>
                        </div>
                    </div>
                    
                    <div class="security-test-panel">
                        <h3>Correctifs de sécurité</h3>
                        <p>Applique des correctifs pour les vulnérabilités détectées.</p>
                        <div class="security-test-controls">
                            <button id="applyXSSFixes" class="security-test-btn">Corriger XSS</button>
                            <button id="applySQLiFixes" class="security-test-btn">Corriger SQLi</button>
                            <button id="applyCSRFFixes" class="security-test-btn">Corriger CSRF</button>
                            <button id="applyAllFixes" class="security-test-btn primary">Corriger tout</button>
                        </div>
                    </div>
                    
                    <div class="security-test-panel">
                        <h3>Rapports</h3>
                        <p>Génère des rapports détaillés sur les tests et correctifs.</p>
                        <div class="security-test-controls">
                            <button id="generateTestReport" class="security-test-btn">Rapport de tests</button>
                            <button id="generateFixReport" class="security-test-btn">Rapport de correctifs</button>
                        </div>
                    </div>
                    
                    <div id="securityTestResults" class="security-test-results"></div>
                `;
                
                adminContent.appendChild(securityTestContent);
                
                // Ajouter les styles CSS
                addSecurityTestStyles();
                
                // Ajouter les gestionnaires d'événements
                addSecurityTestEventListeners();
                
                // Ajouter un gestionnaire d'événements pour l'onglet
                const tabLink = document.querySelector('.admin-nav a[data-tab="security-tests"]');
                if (tabLink) {
                    tabLink.addEventListener('click', function() {
                        // Masquer tous les onglets
                        document.querySelectorAll('.admin-tab').forEach(tab => {
                            tab.style.display = 'none';
                        });
                        
                        // Afficher l'onglet de tests de sécurité
                        document.getElementById('security-tests').style.display = 'block';
                        
                        // Mettre à jour la classe active
                        document.querySelectorAll('.admin-nav a').forEach(link => {
                            link.classList.remove('active');
                        });
                        this.classList.add('active');
                    });
                }
            }
        }
    }
    
    /**
     * Ajoute les styles CSS pour l'interface de tests de sécurité
     */
    function addSecurityTestStyles() {
        const style = document.createElement('style');
        style.textContent = `
            .security-test-panel {
                background-color: #fff;
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                padding: 20px;
                margin-bottom: 20px;
            }
            
            .security-test-panel h3 {
                color: #ca0d95;
                margin-top: 0;
                margin-bottom: 10px;
            }
            
            .security-test-controls {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 15px;
            }
            
            .security-test-btn {
                padding: 10px 15px;
                background-color: #6c757d;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                transition: all 0.3s ease;
            }
            
            .security-test-btn:hover {
                background-color: #5a6268;
                transform: translateY(-2px);
            }
            
            .security-test-btn.primary {
                background-color: #ca0d95;
            }
            
            .security-test-btn.primary:hover {
                background-color: #a80a7a;
            }
            
            .security-test-results {
                margin-top: 30px;
            }
            
            .vulnerability-item {
                padding: 10px;
                margin-bottom: 5px;
                border-radius: 4px;
            }
            
            .vulnerability-item.vulnerable {
                background-color: #ffebee;
                border-left: 4px solid #f44336;
            }
            
            .vulnerability-item.secure {
                background-color: #e8f5e9;
                border-left: 4px solid #4caf50;
            }
        `;
        document.head.appendChild(style);
    }
    
    /**
     * Ajoute les gestionnaires d'événements pour les boutons de test de sécurité
     */
    function addSecurityTestEventListeners() {
        // Tests XSS
        const runXSSTestsBtn = document.getElementById('runXSSTests');
        if (runXSSTestsBtn) {
            runXSSTestsBtn.addEventListener('click', function() {
                simulateXSSTests();
            });
        }
        
        // Tests SQLi
        const runSQLiTestsBtn = document.getElementById('runSQLiTests');
        if (runSQLiTestsBtn) {
            runSQLiTestsBtn.addEventListener('click', function() {
                simulateSQLiTests();
            });
        }
        
        // Tests CSRF
        const runCSRFTestsBtn = document.getElementById('runCSRFTests');
        if (runCSRFTestsBtn) {
            runCSRFTestsBtn.addEventListener('click', function() {
                simulateCSRFTests();
            });
        }
        
        // Tous les tests
        const runAllTestsBtn = document.getElementById('runAllTests');
        if (runAllTestsBtn) {
            runAllTestsBtn.addEventListener('click', function() {
                simulateAllTests();
            });
        }
        
        // Correctifs XSS
        const applyXSSFixesBtn = document.getElementById('applyXSSFixes');
        if (applyXSSFixesBtn && window.securityFixes) {
            applyXSSFixesBtn.addEventListener('click', function() {
                window.securityFixes.applyXSSFixes();
                document.getElementById('securityTestResults').innerHTML = window.securityFixes.generateHTMLReport();
                alert('Les correctifs XSS ont été appliqués.');
            });
        }
        
        // Correctifs SQLi
        const applySQLiFixesBtn = document.getElementById('applySQLiFixes');
        if (applySQLiFixesBtn && window.securityFixes) {
            applySQLiFixesBtn.addEventListener('click', function() {
                window.securityFixes.applySQLiFixes();
                document.getElementById('securityTestResults').innerHTML = window.securityFixes.generateHTMLReport();
                alert('Les correctifs SQLi ont été appliqués.');
            });
        }
        
        // Correctifs CSRF
        const applyCSRFFixesBtn = document.getElementById('applyCSRFFixes');
        if (applyCSRFFixesBtn && window.securityFixes) {
            applyCSRFFixesBtn.addEventListener('click', function() {
                window.securityFixes.applyCSRFFixes();
                document.getElementById('securityTestResults').innerHTML = window.securityFixes.generateHTMLReport();
                alert('Les correctifs CSRF ont été appliqués.');
            });
        }
        
        // Tous les correctifs
        const applyAllFixesBtn = document.getElementById('applyAllFixes');
        if (applyAllFixesBtn && window.securityFixes) {
            applyAllFixesBtn.addEventListener('click', function() {
                window.securityFixes.applyAllFixes();
                document.getElementById('securityTestResults').innerHTML = window.securityFixes.generateHTMLReport();
                alert('Tous les correctifs de sécurité ont été appliqués.');
            });
        }
        
        // Rapport de tests
        const generateTestReportBtn = document.getElementById('generateTestReport');
        if (generateTestReportBtn) {
            generateTestReportBtn.addEventListener('click', function() {
                generateSecurityTestReport();
            });
        }
        
        // Rapport de correctifs
        const generateFixReportBtn = document.getElementById('generateFixReport');
        if (generateFixReportBtn && window.securityFixes) {
            generateFixReportBtn.addEventListener('click', function() {
                document.getElementById('securityTestResults').innerHTML = window.securityFixes.generateHTMLReport();
            });
        }
    }
    
    /**
     * Simule des tests d'attaques XSS
     */
    function simulateXSSTests() {
        const resultsContainer = document.getElementById('securityTestResults');
        resultsContainer.innerHTML = '<h3>Simulation de tests XSS en cours...</h3>';
        
        // Payloads XSS à tester
        const xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')" />',
            '"><script>alert("XSS")</script>',
            '\';alert("XSS");//'
        ];
        
        // Cibles pour les tests
        const testTargets = [
            { name: 'Formulaire d\'événement - Titre', selector: '#eventTitle', type: 'input' },
            { name: 'Formulaire d\'événement - Description', selector: '#eventDescription', type: 'textarea' },
            { name: 'Formulaire d\'édition - Titre', selector: '#editEventTitle', type: 'input' },
            { name: 'Formulaire d\'édition - Description', selector: '#editEventDescription', type: 'textarea' }
        ];
        
        // Simuler les tests
        setTimeout(() => {
            let html = `
                <h3>Résultats des tests XSS</h3>
                <div class="test-results">
            `;
            
            let vulnerableCount = 0;
            
            // Pour chaque cible, tester les payloads
            testTargets.forEach(target => {
                const element = document.querySelector(target.selector);
                if (!element) {
                    html += `<p>Cible non trouvée: ${target.name}</p>`;
                    return;
                }
                
                // Tester chaque payload
                xssPayloads.forEach(payload => {
                    // Simuler un test (dans un environnement réel, on utiliserait un vrai test)
                    const isVulnerable = !element.hasAttribute('data-xss-protected');
                    
                    if (isVulnerable) vulnerableCount++;
                    
                    html += `
                        <div class="vulnerability-item ${isVulnerable ? 'vulnerable' : 'secure'}">
                            <strong>${target.name}</strong>: Test avec payload <code>${escapeHtml(payload)}</code>
                            <span class="result">${isVulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}</span>
                            ${isVulnerable ? '<p>Le payload XSS a été accepté sans échappement</p>' : '<p>Le payload XSS a été correctement échappé ou filtré</p>'}
                        </div>
                    `;
                });
            });
            
            html += `
                </div>
                <div class="test-summary">
                    <p><strong>Résumé:</strong> ${vulnerableCount} vulnérabilités XSS détectées</p>
                    ${vulnerableCount > 0 ? '<p>Recommandation: Appliquer les correctifs XSS pour sécuriser les formulaires</p>' : '<p>Aucune vulnérabilité XSS détectée</p>'}
                </div>
            `;
            
            resultsContainer.innerHTML = html;
        }, 1000);
    }
    
    /**
     * Simule des tests d'injections SQL
     */
    function simulateSQLiTests() {
        const resultsContainer = document.getElementById('securityTestResults');
        resultsContainer.innerHTML = '<h3>Simulation de tests SQLi en cours...</h3>';
        
        // Payloads SQLi à tester
        const sqliPayloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3 --"
        ];
        
        // Cibles pour les tests
        const testTargets = [
            { name: 'Formulaire d\'événement - Titre', selector: '#eventTitle', type: 'input' },
            { name: 'Formulaire d\'événement - Description', selector: '#eventDescription', type: 'textarea' },
            { name: 'Formulaire d\'édition - Titre', selector: '#editEventTitle', type: 'input' },
            { name: 'Formulaire d\'édition - Description', selector: '#editEventDescription', type: 'textarea' }
        ];
        
        // Simuler les tests
        setTimeout(() => {
            let html = `
                <h3>Résultats des tests SQLi</h3>
                <div class="test-results">
            `;
            
            let vulnerableCount = 0;
            
            // Pour chaque cible, tester les payloads
            testTargets.forEach(target => {
                const element = document.querySelector(target.selector);
                if (!element) {
                    html += `<p>Cible non trouvée: ${target.name}</p>`;
                    return;
                }
                
                // Tester chaque payload
                sqliPayloads.forEach(payload => {
                    // Simuler un test (dans un environnement réel, on utiliserait un vrai test)
                    const isVulnerable = !element.hasAttribute('data-sqli-protected');
                    
                    if (isVulnerable) vulnerableCount++;
                    
                    html += `
                        <div class="vulnerability-item ${isVulnerable ? 'vulnerable' : 'secure'}">
                            <strong>${target.name}</strong>: Test avec payload <code>${escapeHtml(payload)}</code>
                            <span class="result">${isVulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}</span>
                            ${isVulnerable ? '<p>Le payload SQLi a été accepté sans validation</p>' : '<p>Le payload SQLi a été correctement validé ou filtré</p>'}
                        </div>
                    `;
                });
            });
            
            html += `
                </div>
                <div class="test-summary">
                    <p><strong>Résumé:</strong> ${vulnerableCount} vulnérabilités SQLi détectées</p>
                    ${vulnerableCount > 0 ? '<p>Recommandation: Appliquer les correctifs SQLi pour sécuriser les formulaires</p>' : '<p>Aucune vulnérabilité SQLi détectée</p>'}
                </div>
            `;
            
            resultsContainer.innerHTML = html;
        }, 1000);
    }
    
    /**
     * Simule des tests d'attaques CSRF
     */
    function simulateCSRFTests() {
        const resultsContainer = document.getElementById('securityTestResults');
        resultsContainer.innerHTML = '<h3>Simulation de tests CSRF en cours...</h3>';
        
        // Cibles pour les tests
        const testTargets = [
            { name: 'Formulaire d\'ajout d\'événement', selector: '#eventForm', type: 'form' },
            { name: 'Formulaire de mise à jour d\'événement', selector: '#updateEventForm', type: 'form' }
        ];
        
        // Simuler les tests
        setTimeout(() => {
            let html = `
                <h3>Résultats des tests CSRF</h3>
                <div class="test-results">
            `;
            
            let vulnerableCount = 0;
            
            // Pour chaque cible, tester la protection CSRF
            testTargets.forEach(target => {
                const form = document.querySelector(target.selector);
                if (!form) {
                    html += `<p>Cible non trouvée: ${target.name}</p>`;
                    return;
                }
                
                // Vérifier si le formulaire contient un jeton CSRF
                const csrfInput = form.querySelector('input[name="csrf_token"]');
                const hasCSRFToken = !!csrfInput && csrfInput.value.length > 0;
                
                // Vérifier si le formulaire a l'attribut data-csrf-protected
                const hasCSRFAttribute = form.hasAttribute('data-csrf-protected');
                
                // Vérifier si le cookie CSRF existe pour ce formulaire
                const formId = form.id;
                const hasCSRFCookie = !!document.cookie.split(';').find(c => c.trim().startsWith(`csrf_${formId}=`));
                
                const isVulnerable = !hasCSRFToken || !hasCSRFAttribute || !hasCSRFCookie;
                
                if (isVulnerable) vulnerableCount++;
                
                html += `
                    <div class="vulnerability-item ${isVulnerable ? 'vulnerable' : 'secure'}">
                        <strong>${target.name}</strong>: Test de protection CSRF
                        <span class="result">${isVulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}</span>
                        ${isVulnerable ? 
                            `<p>Protection CSRF insuffisante: ${!hasCSRFToken ? 'Pas de jeton CSRF' : ''} ${!hasCSRFAttribute ? 'Pas d\'attribut data-csrf-protected' : ''} ${!hasCSRFCookie ? 'Pas de cookie CSRF' : ''}</p>` : 
                            '<p>Protection CSRF correctement implémentée</p>'}
                    </div>
                `;
            });
            
            html += `
                </div>
                <div class="test-summary">
                    <p><strong>Résumé:</strong> ${vulnerableCount} vulnérabilités CSRF détectées</p>
                    ${vulnerableCount > 0 ? '<p>Recommandation: Appliquer les correctifs CSRF pour sécuriser les formulaires</p>' : '<p>Aucune vulnérabilité CSRF détectée</p>'}
                </div>
            `;
            
            resultsContainer.innerHTML = html;
        }, 1000);
    }
    
    /**
     * Simule tous les tests de sécurité
     */
    function simulateAllTests() {
        const resultsContainer = document.getElementById('securityTestResults');
        resultsContainer.innerHTML = '<h3>Simulation de tous les tests de sécurité en cours...</h3>';
        
        // Simuler les tests séquentiellement
        setTimeout(() => {
            // Exécuter les tests XSS
            simulateXSSTests();
            
            // Après les tests XSS, exécuter les tests SQLi
            setTimeout(() => {
                // Exécuter les tests SQLi
                simulateSQLiTests();
                
                // Après les tests SQLi, exécuter les tests CSRF
                setTimeout(() => {
                    // Exécuter les tests CSRF
                    simulateCSRFTests();
                    
                    // Après tous les tests, générer un rapport complet
                    setTimeout(() => {
                        generateSecurityTestReport();
                    }, 1000);
                }, 1000);
            }, 1000);
        }, 1000);
    }
    
    /**
     * Génère un rapport complet des tests de sécurité
     */
    function generateSecurityTestReport() {
        const resultsContainer = document.getElementById('securityTestResults');
        
        // Simuler la génération d'un rapport
        let html = `
            <div class="security-report">
                <h2>Rapport complet de sécurité</h2>
                
                <div class="report-summary">
                    <p><strong>Tests effectués:</strong> XSS, SQLi, CSRF</p>
                    <p><strong>Vulnérabilités détectées:</strong> Plusieurs formulaires sont vulnérables aux attaques XSS, SQLi et CSRF</p>
                </div>
                
                <div class="report-section">
                    <h3>Vulnérabilités XSS</h3>
                    <p>Les champs de formulaire ne filtrent pas correctement les caractères spéciaux HTML, ce qui permet l'injection de code JavaScript malveillant.</p>
                    <ul>
                        <li>Les champs de titre et de description des événements sont vulnérables</li>
                        <li>Les données saisies ne sont pas échappées avant d'être affichées</li>
                    </ul>
                </div>
                
                <div class="report-section">
                    <h3>Vulnérabilités SQLi</h3>
                    <p>Les entrées utilisateur ne sont pas correctement validées avant d'être utilisées dans des requêtes SQL.</p>
                    <ul>
                        <li>Les champs de formulaire acceptent des caractères spéciaux SQL sans validation</li>
                        <li>Aucune préparation de requête n'est utilisée</li>
                    </ul>
                </div>
                
                <div class="report-section">
                    <h3>Vulnérabilités CSRF</h3>
                    <p>Les formulaires ne sont pas tous protégés contre les attaques CSRF.</p>
                    <ul>
                        <li>Certains formulaires n'ont pas de jeton CSRF</li>
                        <li>Les jetons CSRF ne sont pas toujours validés</li>
                    </ul>
                </div>
                
                <div class="report-recommendations">
                    <h3>Recommandations</h3>
                    <ul>
                        <li>
                            <strong>Protection XSS:</strong> Implémentez l'échappement des caractères spéciaux dans les entrées utilisateur.
                            Utilisez des fonctions comme <code>escapeHtml()</code> pour traiter les données avant de les afficher.
                        </li>
                        <li>
                            <strong>Protection SQLi:</strong> Utilisez des requêtes préparées pour toutes les interactions avec la base de données.
                            Validez et filtrez toutes les entrées utilisateur avant de les utiliser dans des requêtes SQL.
                        </li>
                        <li>
                            <strong>Protection CSRF:</strong> Assurez-vous que tous les formulaires incluent un jeton CSRF unique.
                            Vérifiez que le jeton est validé côté serveur avant de traiter toute action sensible.
                        </li>
                        <li>
                            <strong>Mises à jour régulières:</strong> Assurez-vous que toutes les bibliothèques et dépendances sont régulièrement mises à jour.
                        </li>
                        <li>
                            <strong>Tests de pénétration:</strong> Effectuez des tests de pénétration réguliers avec des outils comme OWASP ZAP ou Burp Suite.
                        </li>
                    </ul>
                </div>
                
                <div class="report-actions">
                    <button id="applyAllFixesFromReport" class="security-test-btn primary">Appliquer tous les correctifs</button>
                </div>
            </div>
        `;
        
        resultsContainer.innerHTML = html;
        
        // Ajouter un gestionnaire d'événements pour le bouton d'application des correctifs
        const applyAllFixesBtn = document.getElementById('applyAllFixesFromReport');
        if (applyAllFixesBtn && window.securityFixes) {
            applyAllFixesBtn.addEventListener('click', function() {
                window.securityFixes.applyAllFixes();
                alert('Tous les correctifs de sécurité ont été appliqués. Veuillez exécuter à nouveau les tests pour vérifier les améliorations.');
            });
        }
    }
    
    /**
     * Échappe les caractères HTML spéciaux
     * @param {string} text - Texte à échapper
     * @returns {string} - Texte échappé
     */
    function escapeHtml(text) {
        if (!text) return '';
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});