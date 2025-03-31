/**
 * Module principal de correctifs de sécurité pour Tech Shield
 * Ce module intègre toutes les protections contre les vulnérabilités XSS, SQLi et CSRF
 * et les applique à l'ensemble du site
 */

(function() {
    console.log('Initialisation des correctifs de sécurité...');
    
    /**
     * Charge un script JavaScript de manière asynchrone
     * @param {string} src - URL du script
     * @returns {Promise} - Promise résolue lorsque le script est chargé
     */
    function loadScript(src) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.async = true;
            
            script.onload = () => resolve(script);
            script.onerror = () => reject(new Error(`Erreur lors du chargement du script: ${src}`));
            
            document.head.appendChild(script);
        });
    }
    
    /**
     * Fonction robuste d'échappement HTML pour prévenir les attaques XSS
     * @param {string} text - Texte à échapper
     * @returns {string} - Texte échappé
     */
    function escapeHtml(text) {
        if (text === undefined || text === null) return '';
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;")
            .replace(/`/g, "&#96;")
            .replace(/\//g, "&#47;");
    }
    
    /**
     * Fonction robuste de validation et d'échappement SQL pour prévenir les injections SQL
     * @param {string} text - Texte à valider et échapper
     * @returns {string} - Texte validé et échappé
     */
    function sanitizeSql(text) {
        if (text === undefined || text === null) return '';
        
        // Échapper les caractères spéciaux SQL
        let sanitized = String(text)
            .replace(/'/g, "''")
            .replace(/\\/g, "\\\\")
            .replace(/;/g, "");
        
        // Bloquer les mots-clés SQL dangereux
        const sqlKeywords = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", 
            "EXEC", "UNION", "CREATE", "WHERE", "FROM", "HAVING", "ORDER BY"
        ];
        
        // Remplacer les mots-clés SQL par des versions inoffensives
        sqlKeywords.forEach(keyword => {
            const regex = new RegExp("\\b" + keyword + "\\b", "gi");
            sanitized = sanitized.replace(regex, "BLOCKED_" + keyword);
        });
        
        return sanitized;
    }
    
    /**
     * Applique des correctifs de sécurité immédiats avant le chargement des modules
     */
    function applyImmediateFixes() {
        // Ajouter les méthodes d'échappement aux prototypes String si elles n'existent pas déjà
        if (!String.prototype.escapeHtml) {
            String.prototype.escapeHtml = function() {
                return escapeHtml(this);
            };
        }
        
        if (!String.prototype.sanitizeSql) {
            String.prototype.sanitizeSql = function() {
                return sanitizeSql(this);
            };
        }
        
        // Protéger tous les formulaires existants avec une protection basique
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            // Éviter la double protection
            if (form.hasAttribute('data-security-protected')) return;
            
            // Sauvegarder le gestionnaire d'événements original
            const originalSubmit = form.onsubmit;
            
            // Remplacer le gestionnaire d'événements submit
            form.onsubmit = function(e) {
                // Valider tous les champs avant la soumission
                const inputs = this.querySelectorAll('input[type="text"], input[type="email"], input[type="url"], textarea');
                
                inputs.forEach(input => {
                    // Échapper les caractères HTML et SQL
                    input.value = escapeHtml(sanitizeSql(input.value));
                });
                
                // Appeler le gestionnaire d'événements original s'il existe
                if (typeof originalSubmit === 'function') {
                    return originalSubmit.call(this, e);
                }
            };
            
            // Marquer le formulaire comme protégé
            form.setAttribute('data-security-protected', 'true');
        });
    }
    
    // Appliquer des correctifs immédiats
    applyImmediateFixes();
    
    // Liste des modules de sécurité à charger
    const securityModules = [
        'security-utils.js',
        'xss-protection.js',
        'sql-protection.js',
        'csrf-protection.js',
        'events-security.js',
        'prepared-queries-enhanced.js'
    ];
    
    // Charger tous les modules de sécurité
    Promise.all(securityModules.map(module => loadScript(module)))
        .then(() => {
            console.log('Tous les modules de sécurité ont été chargés avec succès');
            
            // Initialiser les protections une fois tous les modules chargés
            if (window.securityUtils) {
                window.securityUtils.protectAllForms();
            }
            
            if (window.xssProtection) {
                window.xssProtection.protectAllForms();
            }
            
            if (window.sqlProtection) {
                window.sqlProtection.protectAllForms();
            }
            
            if (window.csrfProtection) {
                window.csrfProtection.protectAllForms();
            }
            
            // Journaliser l'initialisation des protections
            if (window.securityLogs) {
                window.securityLogs.addLog({
                    action: 'Sécurité',
                    details: 'Correctifs de sécurité appliqués avec succès',
                    status: window.securityLogs.LOG_TYPES.SUCCESS
                });
            }
        })
        .catch(error => {
            console.error('Erreur lors du chargement des modules de sécurité:', error);
            
            // Journaliser l'erreur
            if (window.securityLogs) {
                window.securityLogs.addLog({
                    action: 'Sécurité',
                    details: `Erreur lors de l'initialisation des correctifs de sécurité: ${error.message}`,
                    status: window.securityLogs.LOG_TYPES.ERROR
                });
            }
        });
    
    // Observer les modifications du DOM pour protéger les nouveaux éléments
    const observer = new MutationObserver(mutations => {
        mutations.forEach(mutation => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    // Protéger les nouveaux formulaires
                    if (node.nodeName === 'FORM' && !node.hasAttribute('data-security-protected')) {
                        // Appliquer une protection basique
                        applyImmediateFixes();
                        
                        // Appliquer les protections avancées si disponibles
                        if (window.securityUtils) {
                            window.securityUtils.protectForm(node);
                        }
                        
                        if (window.xssProtection) {
                            window.xssProtection.protectForm(node);
                        }
                        
                        if (window.sqlProtection) {
                            window.sqlProtection.protectForm(node);
                        }
                        
                        if (window.csrfProtection) {
                            window.csrfProtection.protectForm(node);
                        }
                    }
                    
                    // Rechercher les formulaires dans les sous-éléments
                    if (node.querySelectorAll) {
                        const forms = node.querySelectorAll('form:not([data-security-protected])');
                        if (forms.length > 0) {
                            // Appliquer une protection basique
                            applyImmediateFixes();
                            
                            // Appliquer les protections avancées si disponibles
                            forms.forEach(form => {
                                if (window.securityUtils) {
                                    window.securityUtils.protectForm(form);
                                }
                                
                                if (window.xssProtection) {
                                    window.xssProtection.protectForm(form);
                                }
                                
                                if (window.sqlProtection) {
                                    window.sqlProtection.protectForm(form);
                                }
                                
                                if (window.csrfProtection) {
                                    window.csrfProtection.protectForm(form);
                                }
                            });
                        }
                    }
                });
            }
        });
    });
    
    // Observer tout le document
    observer.observe(document.body, { childList: true, subtree: true });
    
    console.log('Module principal de correctifs de sécurité initialisé');
})();