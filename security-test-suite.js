/**
 * Module de test de sécurité pour Tech Shield
 * Ce module permet de simuler des attaques XSS, SQLi et CSRF pour tester la sécurité du site
 * et générer des rapports d'analyse
 */

window.securityTestSuite = (function() {
    // Configuration du module de test
    const config = {
        // Activer/désactiver les tests
        enabled: true,
        
        // Mode de test (safe: ne modifie pas les données, unsafe: peut modifier les données)
        mode: 'safe',
        
        // Types de tests à exécuter
        tests: {
            xss: true,
            sqli: true,
            csrf: true
        },
        
        // Délai entre les tests (en ms)
        testDelay: 500,
        
        // Nombre maximal de tentatives par test
        maxAttempts: 5,
        
        // Journalisation détaillée
        verboseLogging: true
    };
    
    // Stockage des résultats des tests
    let testResults = {
        xss: [],
        sqli: [],
        csrf: [],
        summary: {
            total: 0,
            passed: 0,
            failed: 0,
            vulnerabilities: 0
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
                error: 'Élément cible non trouvé'
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
                details: isVulnerable ? 'Le payload XSS a été accepté sans échappement' : 'Le payload XSS a été correctement échappé ou filtré'
            };
        } catch (error) {
            return {
                target: target.name,
                payload,
                success: false,
                vulnerable: false,
                error: error.message
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
                error: 'Élément cible non trouvé'
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
                details: isVulnerable ? 'Le payload SQLi a été accepté sans validation' : 'Le payload SQLi a été correctement validé ou filtré'
            };
        } catch (error) {
            return {
                target: target.name,
                payload,
                success: false,
                vulnerable: false,
                error: error.message
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
                error: 'Formulaire cible non trouvé'
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
                    'Protection CSRF correctement implémentée'
            };
        } catch (error) {
            return {
                target: target.name,
                success: false,
                vulnerable: false,
                error: error.message
            };
        }
    }
    
    /**
     * Exécute tous les tests de sécurité
     * @returns {Promise<Object>} - Résultats des tests
     */
    async function runAllTests() {
        if (!config.enabled) {
            console.warn('Les tests de sécurité sont désactivés');
            return testResults;
        }
        
        console.log('Démarrage des tests de sécurité...');
        
        // Réinitialiser les résultats
        testResults = {
            xss: [],
            sqli: [],
            csrf: [],
            summary: {
                total: 0,
                passed: 0,
                failed: 0,
                vulnerabilities: 0
            }
        };
        
        // Exécuter les tests XSS
        if (config.tests.xss) {
            console.log('Exécution des tests XSS...');
            for (const target of testTargets.xss) {
                for (const payload of xssPayloads) {
                    const result = runXSSTest(target, payload);
                    testResults.xss.push(result);
                    testResults.summary.total++;
                    
                    if (result.success) {
                        testResults.summary.passed++;
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
}); else {
                        testResults.summary.failed++;
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                    
                    if (result.vulnerable) {
                        testResults.summary.vulnerabilities++;
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                    
                    if (config.verboseLogging) {
                        console.log(`Test XSS sur ${target.name} avec payload "${payload}": ${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}`);
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                    
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
                    testResults.sqli.push(result);
                    testResults.summary.total++;
                    
                    if (result.success) {
                        testResults.summary.passed++;
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
}); else {
                        testResults.summary.failed++;
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                    
                    if (result.vulnerable) {
                        testResults.summary.vulnerabilities++;
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                    
                    if (config.verboseLogging) {
                        console.log(`Test SQLi sur ${target.name} avec payload "${payload}": ${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}`);
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                    
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
                testResults.csrf.push(result);
                testResults.summary.total++;
                
                if (result.success) {
                    testResults.summary.passed++;
                } else {
                    testResults.summary.failed++;
                }
                
                if (result.vulnerable) {
                    testResults.summary.vulnerabilities++;
                }
                
                if (config.verboseLogging) {
                    console.log(`Test CSRF sur ${target.name}: ${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}`);
                }
                
                // Attendre un peu entre chaque test
                await new Promise(resolve => setTimeout(resolve, config.testDelay));
            }
        }
        
        console.log('Tests de sécurité terminés.');
        console.log(`Résumé: ${testResults.summary.total} tests exécutés, ${testResults.summary.passed} réussis, ${testResults.summary.failed} échoués, ${testResults.summary.vulnerabilities} vulnérabilités détectées.`);
        
        return testResults;
    }
    
    /**
     * Génère un rapport HTML des résultats des tests
     * @returns {string} - Rapport HTML
     */
    function generateHTMLReport() {
        let html = `
        <div class="security-report">
            <h2>Rapport de test de sécurité</h2>
            <div class="report-summary">
                <p><strong>Total des tests:</strong> ${testResults.summary.total}</p>
                <p><strong>Tests réussis:</strong> ${testResults.summary.passed}</p>
                <p><strong>Tests échoués:</strong> ${testResults.summary.failed}</p>
                <p><strong>Vulnérabilités détectées:</strong> ${testResults.summary.vulnerabilities}</p>
            </div>
        `;
        
        // Section XSS
        if (testResults.xss.length > 0) {
            html += `
            <div class="report-section">
                <h3>Tests XSS</h3>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Cible</th>
                            <th>Payload</th>
                            <th>Résultat</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            for (const result of testResults.xss) {
                html += `
                    <tr class="${result.vulnerable ? 'vulnerable' : 'secure'}">
                        <td>${result.target}</td>
                        <td>${escapeHtml(result.payload)}</td>
                        <td>${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}</td>
                        <td>${result.details || result.error || ''}</td>
                    </tr>
                `;
            }
            
            html += `
                    </tbody>
                </table>
            </div>
            `;
        }
        
        // Section SQLi
        if (testResults.sqli.length > 0) {
            html += `
            <div class="report-section">
                <h3>Tests SQLi</h3>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Cible</th>
                            <th>Payload</th>
                            <th>Résultat</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            for (const result of testResults.sqli) {
                html += `
                    <tr class="${result.vulnerable ? 'vulnerable' : 'secure'}">
                        <td>${result.target}</td>
                        <td>${escapeHtml(result.payload)}</td>
                        <td>${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}</td>
                        <td>${result.details || result.error || ''}</td>
                    </tr>
                `;
            }
            
            html += `
                    </tbody>
                </table>
            </div>
            `;
        }
        
        // Section CSRF
        if (testResults.csrf.length > 0) {
            html += `
            <div class="report-section">
                <h3>Tests CSRF</h3>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Cible</th>
                            <th>Résultat</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            for (const result of testResults.csrf) {
                html += `
                    <tr class="${result.vulnerable ? 'vulnerable' : 'secure'}">
                        <td>${result.target}</td>
                        <td>${result.vulnerable ? 'VULNÉRABLE' : 'SÉCURISÉ'}</td>
                        <td>${result.details || result.error || ''}</td>
                    </tr>
                `;
            }
            
            html += `
                    </tbody>
                </table>
            </div>
            `;
        }
        
        html += `
            <div class="report-recommendations">
                <h3>Recommandations</h3>
                <ul>
        `;
        
        // Générer des recommandations basées sur les vulnérabilités détectées
        const xssVulnerabilities = testResults.xss.filter(r => r.vulnerable).length;
        const sqliVulnerabilities = testResults.sqli.filter(r => r.vulnerable).length;
        const csrfVulnerabilities = testResults.csrf.filter(r => r.vulnerable).length;
        
        if (xssVulnerabilities > 0) {
            html += `
                <li>
                    <strong>Protection XSS:</strong> Implémentez l'échappement des caractères spéciaux dans les entrées utilisateur.
                    Utilisez des fonctions comme <code>escapeHtml()</code> pour traiter les données avant de les afficher.
                    Considérez l'utilisation de la politique de sécurité du contenu (CSP) pour limiter les sources de scripts.
                </li>
            `;
        }
        
        if (sqliVulnerabilities > 0) {
            html += `
                <li>
                    <strong>Protection SQLi:</strong> Utilisez des requêtes préparées ou des ORM pour toutes les interactions avec la base de données.
                    Validez et filtrez toutes les entrées utilisateur avant de les utiliser dans des requêtes SQL.
                    Limitez les privilèges de l'utilisateur de base de données au minimum nécessaire.
                </li>
            `;
        }
        
        if (csrfVulnerabilities > 0) {
            html += `
                <li>
                    <strong>Protection CSRF:</strong> Assurez-vous que tous les formulaires incluent un jeton CSRF unique.
                    Vérifiez que le jeton est validé côté serveur avant de traiter toute action sensible.
                    Utilisez l'attribut SameSite=Strict pour les cookies d'authentification.
                </li>
            `;
        }
        
        html += `
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
     */
    function applySecurityFixes() {
        console.log('Application des correctifs de sécurité...');
        
        // Correctifs pour XSS
        const xssVulnerabilities = testResults.xss.filter(r => r.vulnerable).length;
        if (xssVulnerabilities > 0) {
            console.log('Application des correctifs XSS...');
            
            // Ajouter une fonction d'échappement HTML au prototype String
            if (!String.prototype.escapeHtml) {
                String.prototype.escapeHtml = function() {
                    return this
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;")
                        .replace(/'/g, "&#039;");
                };
                console.log('Fonction escapeHtml ajoutée au prototype String');
            }
            
            // Ajouter des validateurs aux champs de formulaire
            const inputFields = document.querySelectorAll('input[type="text"], textarea');
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
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});;
                    field.setAttribute('data-xss-protected', 'true');
                    console.log(`Protection XSS ajoutée au champ ${field.id || field.name || 'sans id'}`);
                }
            });
        }
        
        // Correctifs pour CSRF
        const csrfVulnerabilities = testResults.csrf.filter(r => r.vulnerable).length;
        if (csrfVulnerabilities > 0) {
            console.log('Application des correctifs CSRF...');
            
            // Vérifier si le module CSRF est disponible
            if (window.csrf && window.csrf.protectForms) {
                // Protéger tous les formulaires
                window.csrf.protectForms();
                console.log('Protection CSRF appliquée à tous les formulaires');
            } else {
                console.warn('Module CSRF non disponible, impossible d\'appliquer les correctifs CSRF');
            }
        }
        
        console.log('Application des correctifs de sécurité terminée.');
    }
    
    // Initialiser le module
    function init() {
        console.log('Initialisation du module de test de sécurité...');
        
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
            .report-table tr.vulnerable {
                background-color: #ffebee;
            }
            .report-table tr.secure {
                background-color: #e8f5e9;
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
            .security-test-btn {
                padding: 10px 15px;
                background-color: #ca0d95;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                margin-right: 10px;
                transition: background-color 0.3s;
            }
            .security-test-btn:hover {
                background-color: #a80a7a;
            }
            .security-test-controls {
                margin-bottom: 20px;
            }
        `;
        document.head.appendChild(style);
        
        // Ajouter l'interface utilisateur si nous sommes sur la page d'administration
        if (document.querySelector('.admin-container')) {
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
                    securityTestContent.innerHTML = `
                        <h2>Tests de sécurité</h2>
                        <div class="security-test-controls">
                            <button id="runSecurityTests" class="security-test-btn">Exécuter les tests</button>
                            <button id="applySecurityFixes" class="security-test-btn">Appliquer les correctifs</button>
                        </div>
                        <div id="securityTestResults"></div>
                    `;
                    adminContent.appendChild(securityTestContent);
                    
                    // Ajouter les gestionnaires d'événements
                    document.getElementById('runSecurityTests').addEventListener('click', async function() {
                        const results = await runAllTests();
                        document.getElementById('securityTestResults').innerHTML = generateHTMLReport();
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
}););
                    
                    document.getElementById('applySecurityFixes').addEventListener('click', function() {
                        applySecurityFixes();
                        alert('Les correctifs de sécurité ont été appliqués. Veuillez exécuter à nouveau les tests pour vérifier les améliorations.');
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
}););
                    
                    // Ajouter un gestionnaire d'événements pour l'onglet
                    const tabLink = document.querySelector('.admin-nav a[data-tab="security-tests"]');
                    if (tabLink) {
                        tabLink.addEventListener('click', function() {
                            // Masquer tous les onglets
                            document.querySelectorAll('.admin-tab').forEach(tab => {
                                tab.style.display = 'none';
                            }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
}););
                            
                            // Afficher l'onglet de tests de sécurité
                            document.getElementById('security-tests').style.display = 'block';
                            
                            // Mettre à jour la classe active
                            document.querySelectorAll('.admin-nav a').forEach(link => {
                                link.classList.remove('active');
                            }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
}););
                            this.classList.add('active');
                        }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
}););
                    }
            }
        }
    }
    
    // Exporter les fonctions publiques
    return {
        runAllTests,
        generateHTMLReport,
        applySecurityFixes,
        init,
        config
    };
})();

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le module de test de sécurité
    if (window.securityTestSuite) {
        window.securityTestSuite.init();
    }
});
                }