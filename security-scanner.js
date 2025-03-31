/**
 * Module de scanner de sécurité pour Tech Shield
 * Ce module permet de simuler des attaques XSS, SQLi et CSRF pour tester la sécurité du site
 * et générer des rapports d'analyse similaires à ceux de OWASP ZAP ou Burp Suite
 */

window.securityScanner = (function() {
    // Configuration du scanner
    const config = {
        // Activer/désactiver le scanner
        enabled: true,
        
        // Types de tests à exécuter
        tests: {
            xss: true,   // Cross-Site Scripting
            sqli: true,  // Injection SQL
            csrf: true   // Cross-Site Request Forgery
        },
        
        // Niveau de détail des rapports (1-3)
        verboseLevel: 2,
        
        // Délai entre les tests (en ms)
        testDelay: 300,
        
        // Mode de test (safe: ne modifie pas les données, unsafe: peut modifier les données)
        mode: 'safe'
    };
    
    // Stockage des résultats des tests
    let scanResults = {
        xss: [],
        sqli: [],
        csrf: [],
        summary: {
            total: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        }
    };
    
    // Payloads pour les tests XSS
    const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '"><script>alert("XSS")</script>',
        '\';alert("XSS");//',
        '<div onmouseover="alert(\'XSS\')">\'Passez la souris ici\'</div>',
        '<iframe src="javascript:alert(\'XSS\');"></iframe>',
        '<svg onload="alert(\'XSS\')" />',
        '" onmouseover="alert(\'XSS\')',
        '<a href="javascript:alert(\'XSS\')">Cliquez ici</a>',
        '<body onload="alert(\'XSS\')"'
    ];
    
    // Payloads pour les tests SQLi
    const sqliPayloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT 1,2,3 --",
        "'; DROP TABLE users; --",
        "' OR '1'='1' UNION SELECT 1,2,3 --",
        "' OR username LIKE '%admin%",
        "' AND 1=0 UNION SELECT 1,2,3 --",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --"
    ];
    
    // Cibles pour les tests
    const testTargets = {
        xss: [
            { name: 'Formulaire d\'événement - Titre', selector: '#eventTitle', type: 'input' },
            { name: 'Formulaire d\'événement - Description', selector: '#eventDescription', type: 'textarea' },
            { name: 'Formulaire d\'édition - Titre', selector: '#editEventTitle', type: 'input' },
            { name: 'Formulaire d\'édition - Description', selector: '#editEventDescription', type: 'textarea' }
        ],
        sqli: [
            { name: 'Formulaire d\'événement - Titre', selector: '#eventTitle', type: 'input' },
            { name: 'Formulaire d\'événement - Description', selector: '#eventDescription', type: 'textarea' },
            { name: 'Formulaire d\'édition - Titre', selector: '#editEventTitle', type: 'input' },
            { name: 'Formulaire d\'édition - Description', selector: '#editEventDescription', type: 'textarea' }
        ],
        csrf: [
            { name: 'Formulaire d\'ajout d\'événement', selector: '#eventForm', type: 'form' },
            { name: 'Formulaire de mise à jour d\'événement', selector: '#updateEventForm', type: 'form' }
        ]
    };
    
    /**
     * Exécute un test XSS sur une cible
     * @param {Object} target - Cible du test
     * @param {string} payload - Payload XSS à tester
     * @returns {Object} - Résultat du test
     */
    function runXSSTest(target, payload) {
        const element = document.querySelector(target.selector);
        if (!element) {
            return {
                target: target.name,
                payload,
                success: false,
                vulnerable: false,
                error: 'Élément cible non trouvé',
                severity: 'info'
            };
        }
        
        try {
            // Sauvegarder la valeur originale
            const originalValue = element.value;
            
            // Injecter le payload
            element.value = payload;
            
            // Vérifier si le payload a été accepté tel quel
            const isVulnerable = element.value === payload;
            
            // Restaurer la valeur originale
            element.value = originalValue;
            
            return {
                target: target.name,
                payload,
                success: true,
                vulnerable: isVulnerable,
                details: isVulnerable ? 'Le payload XSS a été accepté sans échappement' : 'Le payload XSS a été correctement échappé ou filtré',
                severity: isVulnerable ? 'high' : 'info'
            };
        } catch (error) {
            return {
                target: target.name,
                payload,
                success: false,
                vulnerable: false,
                error: error.message,
                severity: 'info'
            };
        }
    }
    
    /**
     * Exécute un test SQLi sur une cible
     * @param {Object} target - Cible du test
     * @param {string} payload - Payload SQLi à tester
     * @returns {Object} - Résultat du test
     */
    function runSQLiTest(target, payload) {
        const element = document.querySelector(target.selector);
        if (!element) {
            return {
                target: target.name,
                payload,
                success: false,
                vulnerable: false,
                error: 'Élément cible non trouvé',
                severity: 'info'
            };
        }
        
        try {
            // Sauvegarder la valeur originale
            const originalValue = element.value;
            
            // Injecter le payload
            element.value = payload;
            
            // Vérifier si le payload a été accepté tel quel
            const isVulnerable = element.value === payload;
            
            // Restaurer la valeur originale
            element.value = originalValue;
            
            return {
                target: target.name,
                payload,
                success: true,
                vulnerable: isVulnerable,
                details: isVulnerable ? 'Le payload SQLi a été accepté sans validation' : 'Le payload SQLi a été correctement validé ou filtré',
                severity: isVulnerable ? 'high' : 'info'
            };
        } catch (error) {
            return {
                target: target.name,
                payload,
                success: false,
                vulnerable: false,
                error: error.message,
                severity: 'info'
            };
        }
    }
    
    /**
     * Exécute un test CSRF sur une cible
     * @param {Object} target - Cible du test
     * @returns {Object} - Résultat du test
     */
    function runCSRFTest(target) {
        const form = document.querySelector(target.selector);
        if (!form) {
            return {
                target: target.name,
                success: false,
                vulnerable: false,
                error: 'Formulaire cible non trouvé',
                severity: 'info'
            };
        }
        
        try {
            // Vérifier si le formulaire contient un jeton CSRF
            const csrfInput = form.querySelector('input[name="csrf_token"]');
            const hasCSRFToken = !!csrfInput && csrfInput.value.length > 0;
            
            // Vérifier si le formulaire a l'attribut data-csrf-protected
            const hasCSRFAttribute = form.hasAttribute('data-csrf-protected');
            
            // Vérifier si le cookie CSRF existe pour ce formulaire
            const formId = form.id;
            const hasCSRFCookie = !!document.cookie.split(';').find(c => c.trim().startsWith(`csrf_${formId}=`));
            
            const isVulnerable = !hasCSRFToken || !hasCSRFAttribute || !hasCSRFCookie;
            
            return {
                target: target.name,
                success: true,
                vulnerable: isVulnerable,
                details: isVulnerable ? 
                    `Protection CSRF insuffisante: ${!hasCSRFToken ? 'Pas de jeton CSRF' : ''} ${!hasCSRFAttribute ? 'Pas d\'attribut data-csrf-protected' : ''} ${!hasCSRFCookie ? 'Pas de cookie CSRF' : ''}`.trim() : 
                    'Protection CSRF correctement implémentée',
                severity: isVulnerable ? 'medium' : 'info'
            };
        } catch (error) {
            return {
                target: target.name,
                success: false,
                vulnerable: false,
                error: error.message,
                severity: 'info'
            };
        }
    }
    
    /**
     * Exécute tous les tests de sécurité
     * @returns {Promise<Object>} - Résultats des tests
     */
    async function runAllTests() {
        if (!config.enabled) {
            console.warn('Le scanner de sécurité est désactivé');
            return scanResults;
        }
        
        console.log('Démarrage du scan de sécurité...');
        
        // Réinitialiser les résultats
        scanResults = {
            xss: [],
            sqli: [],
            csrf: [],
            summary: {
                total: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            }
        };
        
        // Exécuter les tests XSS
        if (config.tests.xss) {
            console.log('Exécution des tests XSS...');
            for (const target of testTargets.xss) {
                for (const payload of xssPayloads) {
                    const result = runXSSTest(target, payload);
                    scanResults.xss.push(result);
                    scanResults.summary.total++;
                    
                    if (result.vulnerable) {
                        scanResults.summary[result.severity]++;
                    } else {
                        scanResults.summary.info++;
                    }
                    
                    if (config.verboseLevel >= 2) {
                        console.log(`Test XSS sur ${target.name} avec payload "${payload}": ${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}`);
                    }
                    
                    // Attendre un peu entre chaque test
                    await new Promise(resolve => setTimeout(resolve, config.testDelay));
                }
            }
        }
        
        // Exécuter les tests SQLi
        if (config.tests.sqli) {
            console.log('Exécution des tests SQLi...');
            for (const target of testTargets.sqli) {
                for (const payload of sqliPayloads) {
                    const result = runSQLiTest(target, payload);
                    scanResults.sqli.push(result);
                    scanResults.summary.total++;
                    
                    if (result.vulnerable) {
                        scanResults.summary[result.severity]++;
                    } else {
                        scanResults.summary.info++;
                    }
                    
                    if (config.verboseLevel >= 2) {
                        console.log(`Test SQLi sur ${target.name} avec payload "${payload}": ${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}`);
                    }
                    
                    // Attendre un peu entre chaque test
                    await new Promise(resolve => setTimeout(resolve, config.testDelay));
                }
            }
        }
        
        // Exécuter les tests CSRF
        if (config.tests.csrf) {
            console.log('Exécution des tests CSRF...');
            for (const target of testTargets.csrf) {
                const result = runCSRFTest(target);
                scanResults.csrf.push(result);
                scanResults.summary.total++;
                
                if (result.vulnerable) {
                    scanResults.summary[result.severity]++;
                } else {
                    scanResults.summary.info++;
                }
                
                if (config.verboseLevel >= 2) {
                    console.log(`Test CSRF sur ${target.name}: ${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}`);
                }
                
                // Attendre un peu entre chaque test
                await new Promise(resolve => setTimeout(resolve, config.testDelay));
            }
        }
        
        console.log('Scan de sécurité terminé.');
        console.log(`Résumé: ${scanResults.summary.total} tests exécutés, ${scanResults.summary.high} vulnérabilités critiques, ${scanResults.summary.medium} moyennes, ${scanResults.summary.low} faibles.`);
        
        return scanResults;
    }
    
    /**
     * Génère un rapport HTML des résultats du scan
     * @returns {string} - Rapport HTML
     */
    function generateHTMLReport() {
        let html = `
        <div class="security-report">
            <h2>Rapport de scan de sécurité</h2>
            <div class="report-summary">
                <p><strong>Total des tests:</strong> ${scanResults.summary.total}</p>
                <p><strong>Vulnérabilités critiques:</strong> ${scanResults.summary.high}</p>
                <p><strong>Vulnérabilités moyennes:</strong> ${scanResults.summary.medium}</p>
                <p><strong>Vulnérabilités faibles:</strong> ${scanResults.summary.low}</p>
                <p><strong>Informations:</strong> ${scanResults.summary.info}</p>
            </div>
        `;
        
        // Section XSS
        if (scanResults.xss.length > 0) {
            const vulnerableXSS = scanResults.xss.filter(r => r.vulnerable);
            
            html += `
            <div class="report-section">
                <h3>Vulnérabilités XSS (${vulnerableXSS.length})</h3>
            `;
            
            if (vulnerableXSS.length > 0) {
                html += `
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Cible</th>
                            <th>Payload</th>
                            <th>Sévérité</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody>
                `;
                
                for (const result of vulnerableXSS) {
                    html += `
                        <tr class="severity-${result.severity}">
                            <td>${result.target}</td>
                            <td>${escapeHtml(result.payload)}</td>
                            <td>${result.severity.toUpperCase()}</td>
                            <td>${result.details || result.error || ''}</td>
                        </tr>
                    `;
                }
                
                html += `
                    </tbody>
                </table>
                `;
            } else {
                html += `<p>Aucune vulnérabilité XSS détectée.</p>`;
            }
            
            html += `</div>`;
        }
        
        // Section SQLi
        if (scanResults.sqli.length > 0) {
            const vulnerableSQLi = scanResults.sqli.filter(r => r.vulnerable);
            
            html += `
            <div class="report-section">
                <h3>Vulnérabilités SQLi (${vulnerableSQLi.length})</h3>
            `;
            
            if (vulnerableSQLi.length > 0) {
                html += `
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Cible</th>
                            <th>Payload</th>
                            <th>Sévérité</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody>
                `;
                
                for (const result of vulnerableSQLi) {
                    html += `
                        <tr class="severity-${result.severity}">
                            <td>${result.target}</td>
                            <td>${escapeHtml(result.payload)}</td>
                            <td>${result.severity.toUpperCase()}</td>
                            <td>${result.details || result.error || ''}</td>
                        </tr>
                    `;
                }
                
                html += `
                    </tbody>
                </table>
                `;
            } else {
                html += `<p>Aucune vulnérabilité SQLi détectée.</p>`;
            }
            
            html += `</div>`;
        }
        
        // Section CSRF
        if (scanResults.csrf.length > 0) {
            const vulnerableCSRF = scanResults.csrf.filter(r => r.vulnerable);
            
            html += `
            <div class="report-section">
                <h3>Vulnérabilités CSRF (${vulnerableCSRF.length})</h3>
            `;
            
            if (vulnerableCSRF.length > 0) {
                html += `
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Cible</th>
                            <th>Sévérité</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody>
                `;
                
                for (const result of vulnerableCSRF) {
                    html += `
                        <tr class="severity-${result.severity}">
                            <td>${result.target}</td>
                            <td>${result.severity.toUpperCase()}</td>
                            <td>${result.details || result.error || ''}</td>
                        </tr>
                    `;
                }
                
                html += `
                    </tbody>
                </table>
                `;
            } else {
                html += `<p>Aucune vulnérabilité CSRF détectée.</p>`;
            }
            
            html += `</div>`;
        }
        
        // Section recommandations
        html += `
            <div class="report-recommendations">
                <h3>Recommandations</h3>
                <ul>
        `;
        
        // Générer des recommandations basées sur les vulnérabilités détectées
        const vulnerableXSS = scanResults.xss.filter(r => r.vulnerable).length;
        const vulnerableSQLi = scanResults.sqli.filter(r => r.vulnerable).length;
        const vulnerableCSRF = scanResults.csrf.filter(r => r.vulnerable).length;
        
        if (vulnerableXSS > 0) {
            html += `
                <li>
                    <strong>Protection XSS:</strong>
                    <ul>
                        <li>Implémentez l'échappement des caractères spéciaux dans les entrées utilisateur.</li>
                        <li>Utilisez des fonctions comme <code>escapeHtml()</code> pour traiter les données avant de les afficher.</li>
                        <li>Considérez l'utilisation de la politique de sécurité du contenu (CSP) pour limiter les sources de scripts.</li>
                        <li>Validez toutes les entrées utilisateur côté serveur et côté client.</li>
                    </ul>
                </li>
            `;
        }
        
        if (vulnerableSQLi > 0) {
            html += `
                <li>
                    <strong>Protection SQLi:</strong>
                    <ul>
                        <li>Utilisez des requêtes préparées ou des ORM pour toutes les interactions avec la base de données.</li>
                        <li>Validez et filtrez toutes les entrées utilisateur avant de les utiliser dans des requêtes SQL.</li>
                        <li>Limitez les privilèges de l'utilisateur de base de données au minimum nécessaire.</li>
                        <li>Utilisez des listes blanches pour valider les entrées plutôt que des listes noires.</li>
                    </ul>
                </li>
            `;
        }
        
        if (vulnerableCSRF > 0) {
            html += `
                <li>
                    <strong>Protection CSRF:</strong>
                    <ul>
                        <li>Assurez-vous que tous les formulaires incluent un jeton CSRF unique.</li>
                        <li>Vérifiez que le jeton est validé côté serveur avant de traiter toute action sensible.</li>
                        <li>Utilisez l'attribut SameSite=Strict pour les cookies d'authentification.</li>
                        <li>Implémentez une vérification de l'en-tête Referer pour les requêtes sensibles.</li>
                    </ul>
                </li>
            `;
        }
        
        html += `
                <li>
                    <strong>Recommandations générales:</strong>
                    <ul>
                        <li>Effectuez des tests de sécurité réguliers avec des outils comme OWASP ZAP ou Burp Suite.</li>
                        <li>Maintenez toutes les bibliothèques et dépendances à jour.</li>
                        <li>Implémentez une politique de sécurité stricte et formez les développeurs aux bonnes pratiques.</li>
                        <li>Utilisez HTTPS pour toutes les communications.</li>
                    </ul>
                </li>
            </ul>
            </div>
        </div>
        `;
        
        return html;
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
    
    /**
     * Applique les correctifs recommandés pour les vulnérabilités détectées
     * @returns {Object} - Résultat de l'application des correctifs
     */
    function applyRecommendedFixes() {
        console.log('Application des correctifs recommandés...');
        
        const fixResults = {
            xss: { applied: false, details: '' },
            sqli: { applied: false, details: '' },
            csrf: { applied: false, details: '' }
        };
        
        // Correctifs pour XSS
        const vulnerableXSS = scanResults.xss.filter(r => r.vulnerable).length;
        if (vulnerableXSS > 0) {
            try {
                // Ajouter une fonction d'échappement HTML au prototype String
                if (!String.prototype.escapeHtml) {
                    String.prototype.escapeHtml = function() {
                        return escapeHtml(this);
                    };
                }
                
                // Ajouter des validateurs aux champs de formulaire
                const inputFields = document.querySelectorAll('input[type="text"], textarea');
                let protectedCount = 0;
                
                inputFields.forEach(field => {
                    if (!field.hasAttribute('data-xss-protected')) {
                        const originalOnChange = field.onchange;
                        field.onchange = function(e) {
                            // Échapper les caractères spéciaux
                            this.value = this.value.escapeHtml();
                            
                            // Appeler le gestionnaire d'événements original s'il existe
                            if (typeof originalOnChange === 'function') {
                                originalOnChange.call(this, e);
                            }
                        };
                        field.setAttribute('data-xss-protected', 'true');
                        protectedCount++;
                    }
                });
                
                fixResults.xss.applied = true;
                fixResults.xss.details = `Protection XSS appliquée à ${protectedCount} champs de formulaire.`;
            } catch (error) {
                fixResults.xss.details = `Erreur lors de l'application des correctifs XSS: ${error.message}`;
            }
        } else {
            fixResults.xss.details = 'Aucune vulnérabilité XSS détectée, pas de correctif nécessaire.';
        }
        
        // Correctifs pour SQLi
        const vulnerableSQLi = scanResults.sqli.filter(r => r.vulnerable).length;
        if (vulnerableSQLi > 0) {
            try {
                // Ajouter une fonction de validation SQL au prototype String
                if (!String.prototype.sanitizeSql) {
                    String.prototype.sanitizeSql = function() {
                        // Échapper les caractères spéciaux SQL
                        return this
                            .replace(/'/g, "''")
                            .replace(/\\/g, "\\\\")
                            .replace(/;/g, "");
                    };
                }
                
                // Ajouter des validateurs aux champs de formulaire
                const inputFields = document.querySelectorAll('input[type="text"], textarea');
                let protectedCount = 0;
                
                inputFields.forEach(field => {
                    if (!field.hasAttribute('data-sqli-protected')) {
                        const originalOnChange = field.onchange;
                        field.onchange = function(e) {
                            // Échapper les caractères spéciaux SQL
                            this.value = this.value.sanitizeSql();
                            
                            // Appeler le gestionnaire d'événements original s'il existe
                            if (typeof originalOnChange === 'function') {
                                originalOnChange.call(this, e);
                            }
                        };
                        field.setAttribute('data-sqli-protected', 'true');
                        protectedCount++;
                    }
                });
                
                fixResults.sqli.applied = true;
                fixResults.sqli.details = `Protection SQLi appliquée à ${protectedCount} champs de formulaire.`;
            } catch (error) {
                fixResults.sqli.details = `Erreur lors de l'application des correctifs SQLi: ${error.message}`;
            }
        } else {
            fixResults.sqli.details = 'Aucune vulnérabilité SQLi détectée, pas de correctif nécessaire.';
        }
        
        // Correctifs pour CSRF
        const vulnerableCSRF = scanResults.csrf.filter(r => r.vulnerable).length;
        if (vulnerableCSRF > 0) {
            try {
                // Vérifier si le module CSRF est disponible
                if (window.csrf && window.csrf.protectForms) {
                    // Protéger tous les formulaires
                    window.csrf.protectForms();
                    
                    // Vérifier que tous les formulaires sont protégés
                    const forms = document.querySelectorAll('form');
                    let protectedCount = 0;
                    
                    forms.forEach(form => {
                        const hasCSRFToken = !!form.querySelector('input[name="csrf_token"]');
                        const hasCSRFAttribute = form.hasAttribute('data-csrf-protected');
                        
                        if (hasCSRFToken && hasCSRFAttribute) {
                            protectedCount++;
                        }
                    });
                    
                    fixResults.csrf.applied = true;
                    fixResults.csrf.details = `Protection CSRF appliquée à ${protectedCount} formulaires.`;
                } else {
                    fixResults.csrf.details = 'Module CSRF non disponible, impossible d\'appliquer les correctifs CSRF.';
                }
            } catch (error) {
                fixResults.csrf.details = `Erreur lors de l'application des correctifs CSRF: ${error.message}`;
            }
        } else {
            fixResults.csrf.details = 'Aucune vulnérabilité CSRF détectée, pas de correctif nécessaire.';
        }
        
        console.log('Application des correctifs terminée.');
        return fixResults;
    }
    
    /**
     * Initialise le module de scanner de sécurité
     */
    function init() {
        console.log('Initialisation du scanner de sécurité...');
        
        // Ajouter des styles CSS pour le rapport
        const style = document.createElement('style');
        style.textContent = `
            .security-report {
                font-family: Arial, sans-serif;
                max-width: 1200px;
                margin: 20px auto;
                padding: 20px;
                background-color: #f8f9fa;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .security-report h2 {
                color: #ca0d95;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
                margin-bottom: 20px;
            }
            .security-report h3 {
                color: #333;
                margin-top: 20px;
                margin-bottom: 10px;
            }
            .report-summary {
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
                margin-bottom: 20px;
                background-color: #fff;
                padding: 15px;
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .report-summary p {
                margin: 0;
                flex: 1 0 200px;
            }
            .report-table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
                background-color: #fff;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .report-table th, .report-table td {
                padding: 10px;
                text-align: left;
                border-bottom: 1px solid #eee;
            }
            .report-table th {
                background-color: #f1f1f1;
                font-weight: bold;
            }
            .severity-high {
                background-color: #ffebee;
            }
            .severity-medium {
                background-color: #fff8e1;
            }
            .severity-low {
                background-color: #e8f5e9;
            }
            .severity-info {
                background-color: #e3f2fd;
            }
            .report-recommendations {
                background-color: #fff;
                padding: 15px;
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .report-recommendations ul {
                padding-left: 20px;
            }
            .report-recommendations li {
                margin-bottom: 10px;
            }
        `;
        document.head.appendChild(style);
        
        console.log('Scanner de sécurité initialisé');
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applyRecommendedFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le scanner de sécurité
    if (window.securityScanner) {
        window.securityScanner.init();
    }
});