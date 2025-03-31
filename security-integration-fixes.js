/**
 * Module d'intégration des correctifs de sécurité pour Tech Shield
 * Ce module charge et initialise toutes les protections contre les vulnérabilités XSS, SQLi et CSRF
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log('Initialisation des correctifs de sécurité...');
    
    // Configuration globale des protections
    const securityConfig = {
        // Activer/désactiver les protections
        enabled: true,
        
        // Types de protections
        protections: {
            xss: true,   // Protection contre les attaques XSS
            sqli: true,  // Protection contre les injections SQL
            csrf: true   // Protection contre les attaques CSRF
        },
        
        // Journalisation détaillée
        verboseLogging: true
    };
    
    // Exposer la configuration pour les autres modules
    window.securityFixesConfig = securityConfig;
    
    /**
     * Charge un script JavaScript de manière asynchrone
     * @param {string} src - URL du script
     * @param {Function} callback - Fonction de rappel après chargement
     */
    function loadScript(src, callback) {
        const script = document.createElement('script');
        script.src = src;
        script.async = true;
        
        script.onload = function() {
            if (typeof callback === 'function') {
                callback();
            }
        };
        
        script.onerror = function() {
            console.error(`Erreur lors du chargement du script: ${src}`);
        };
        
        document.head.appendChild(script);
    }
    
    /**
     * Initialise les protections après le chargement des scripts
     */
    function initializeProtections() {
        console.log('Initialisation des protections de sécurité...');
        
        // Vérifier que tous les modules sont chargés
        const modulesLoaded = {
            xss: typeof window.xssProtection !== 'undefined',
            sql: typeof window.sqlProtection !== 'undefined',
            csrf: typeof window.csrfProtection !== 'undefined',
            utils: typeof window.securityUtils !== 'undefined'
        };
        
        console.log('État des modules:', modulesLoaded);
        
        // Appliquer les protections XSS
        if (securityConfig.protections.xss && modulesLoaded.xss) {
            // Protéger tous les formulaires contre les attaques XSS
            window.xssProtection.protectAllForms();
            console.log('Protection XSS activée');
        }
        
        // Appliquer les protections SQLi
        if (securityConfig.protections.sqli && modulesLoaded.sql) {
            // Protéger tous les formulaires contre les injections SQL
            window.sqlProtection.protectAllForms();
            console.log('Protection SQLi activée');
        }
        
        // Appliquer les protections CSRF
        if (securityConfig.protections.csrf && modulesLoaded.csrf) {
            // Protéger tous les formulaires contre les attaques CSRF
            window.csrfProtection.protectAllForms();
            console.log('Protection CSRF activée');
        }
        
        // Appliquer les protections générales
        if (modulesLoaded.utils) {
            // Protéger tous les formulaires avec les utilitaires de sécurité
            window.securityUtils.protectAllForms();
            console.log('Utilitaires de sécurité activés');
        }
        
        // Journaliser l'initialisation des protections
        if (window.securityLogs) {
            window.securityLogs.addLog({
                action: 'Sécurité',
                details: 'Protections de sécurité initialisées',
                status: window.securityLogs.LOG_TYPES.INFO
            });
        }
        
        console.log('Initialisation des protections de sécurité terminée');
    }
    
    // Charger les scripts de protection dans l'ordre
    loadScript('security-utils.js', function() {
        loadScript('xss-protection.js', function() {
            loadScript('sql-protection.js', function() {
                loadScript('csrf-protection.js', function() {
                    // Initialiser les protections une fois tous les scripts chargés
                    initializeProtections();
                });
            });
        });
    });
    
    /**
     * Applique les correctifs de sécurité aux formulaires existants
     */
    function applySecurityFixes() {
        // Sélectionner tous les formulaires
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            // Ajouter un attribut pour éviter la double protection
            if (form.hasAttribute('data-security-fixed')) return;
            
            // Sauvegarder le gestionnaire d'événements original
            const originalSubmit = form.onsubmit;
            
            // Remplacer le gestionnaire d'événements submit
            form.onsubmit = function(e) {
                // Valider tous les champs avant la soumission
                const inputs = this.querySelectorAll('input[type="text"], input[type="email"], input[type="url"], textarea');
                let isValid = true;
                
                inputs.forEach(input => {
                    // Échapper les caractères HTML et SQL
                    if (window.securityUtils) {
                        const validation = window.securityUtils.validateInput(input.value);
                        if (!validation.valid) {
                            isValid = false;
                            alert(validation.message || 'Entrée invalide détectée');
                        } else {
                            input.value = validation.sanitized;
                        }
                    } else {
                        // Fallback si les modules ne sont pas chargés
                        input.value = input.value
                            .replace(/</g, '&lt;')
                            .replace(/>/g, '&gt;')
                            .replace(/"/g, '&quot;')
                            .replace(/'/g, '&#039;')
                            .replace(/`/g, '&#96;')
                            .replace(/;/g, '');
                    }
                });
                
                // Vérifier le jeton CSRF si le module est disponible
                if (window.csrfProtection) {
                    const formId = form.id || 'form_' + Math.random().toString(36).substr(2, 9);
                    const csrfInput = form.querySelector('input[name="csrf_token"]');
                    
                    if (!csrfInput) {
                        // Ajouter un jeton CSRF si manquant
                        window.csrfProtection.addCSRFTokenToForm(form);
                    } else if (!window.csrfProtection.validateCSRFToken(formId, csrfInput.value)) {
                        isValid = false;
                        alert('Erreur de sécurité: jeton CSRF invalide. Veuillez rafraîchir la page et réessayer.');
                    }
                }
                
                // Empêcher la soumission si le formulaire n'est pas valide
                if (!isValid) {
                    e.preventDefault();
                    return false;
                }
                
                // Appeler le gestionnaire d'événements original s'il existe
                if (typeof originalSubmit === 'function') {
                    return originalSubmit.call(this, e);
                }
            };
            
            // Marquer le formulaire comme protégé
            form.setAttribute('data-security-fixed', 'true');
        });
    }
    
    // Appliquer les correctifs de sécurité aux formulaires existants
    setTimeout(applySecurityFixes, 500);
    
    // Observer les modifications du DOM pour appliquer les correctifs aux nouveaux formulaires
    const observer = new MutationObserver(mutations => {
        mutations.forEach(mutation => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    // Appliquer les correctifs aux nouveaux formulaires
                    if (node.nodeName === 'FORM') {
                        setTimeout(() => {
                            if (!node.hasAttribute('data-security-fixed')) {
                                applySecurityFixes();
                            }
                        }, 0);
                    }
                    
                    // Rechercher les formulaires dans les sous-éléments
                    if (node.querySelectorAll) {
                        const forms = node.querySelectorAll('form:not([data-security-fixed])');
                        if (forms.length > 0) {
                            setTimeout(applySecurityFixes, 0);
                        }
                    }
                });
            }
        });
    });
    
    // Observer tout le document
    observer.observe(document.body, { childList: true, subtree: true });
    
    console.log('Module d\'intégration des correctifs de sécurité initialisé');
});