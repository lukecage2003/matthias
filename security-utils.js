/**
 * Module d'utilitaires de sécurité pour Tech Shield
 * Ce module fournit des fonctions robustes pour protéger contre les vulnérabilités XSS, SQLi et CSRF
 */

window.securityUtils = (function() {
    // Configuration des protections
    const config = {
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
    
    /**
     * Fonction robuste d'échappement HTML pour prévenir les attaques XSS
     * @param {string} text - Texte à échapper
     * @returns {string} - Texte échappé
     */
    function escapeHtml(text) {
        if (!text) return '';
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
        if (!text) return '';
        
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
     * Valide une entrée utilisateur pour détecter les tentatives d'injection
     * @param {string} input - Entrée à valider
     * @param {string} type - Type de validation ('text', 'email', 'url', etc.)
     * @returns {Object} - Résultat de la validation {valid: boolean, sanitized: string}
     */
    function validateInput(input, type = 'text') {
        if (input === undefined || input === null) {
            return { valid: false, sanitized: '', message: 'Entrée invalide' };
        }
        
        const inputStr = String(input).trim();
        let valid = true;
        let sanitized = inputStr;
        let message = '';
        
        // Validation selon le type
        switch (type.toLowerCase()) {
            case 'email':
                const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
                valid = emailRegex.test(inputStr);
                if (!valid) message = 'Format d\'email invalide';
                break;
                
            case 'url':
                try {
                    new URL(inputStr);
                    valid = true;
                } catch (e) {
                    valid = false;
                    message = 'URL invalide';
                }
                break;
                
            case 'number':
                valid = !isNaN(Number(inputStr));
                if (valid) sanitized = Number(inputStr);
                if (!valid) message = 'Format de nombre invalide';
                break;
                
            case 'date':
                const date = new Date(inputStr);
                valid = !isNaN(date.getTime());
                if (!valid) message = 'Format de date invalide';
                break;
                
            case 'text':
            default:
                // Détecter les tentatives d'injection XSS
                const xssPatterns = [/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, /on\w+\s*=/gi, /javascript:/gi];
                const containsXSS = xssPatterns.some(pattern => pattern.test(inputStr));
                
                // Détecter les tentatives d'injection SQL
                const sqlPatterns = /('(''|[^'])*')|(;\s*SELECT)|(;\s*INSERT)|(;\s*UPDATE)|(;\s*DELETE)|(;\s*DROP)|(\/\*[\s\S]*?\*\/)|(--)|(#)/gi;
                const containsSQL = sqlPatterns.test(inputStr);
                
                if (containsXSS) {
                    valid = false;
                    message = 'Tentative d\'injection XSS détectée';
                    
                    // Journaliser la tentative d'attaque
                    if (window.securityLogs) {
                        window.securityLogs.addLog({
                            action: 'Tentative d\'attaque',
                            details: `Tentative d'injection XSS détectée: ${escapeHtml(inputStr)}`,
                            status: window.securityLogs.LOG_TYPES.DANGER
                        });
                    }
                } else if (containsSQL) {
                    valid = false;
                    message = 'Tentative d\'injection SQL détectée';
                    
                    // Journaliser la tentative d'attaque
                    if (window.securityLogs) {
                        window.securityLogs.addLog({
                            action: 'Tentative d\'attaque',
                            details: `Tentative d'injection SQL détectée: ${escapeHtml(inputStr)}`,
                            status: window.securityLogs.LOG_TYPES.DANGER
                        });
                    }
                }
                
                // Échapper le HTML et le SQL dans tous les cas
                sanitized = escapeHtml(sanitizeSql(inputStr));
                break;
        }
        
        return { valid, sanitized, message };
    }
    
    /**
     * Protège un formulaire contre les attaques XSS et SQLi
     * @param {HTMLFormElement} form - Formulaire à protéger
     */
    function protectForm(form) {
        if (!form || !(form instanceof HTMLFormElement)) return;
        
        // Éviter la double protection
        if (form.hasAttribute('data-security-protected')) return;
        
        // Protéger contre XSS
        if (config.protections.xss) {
            // Ajouter un attribut pour marquer le formulaire comme protégé contre XSS
            form.setAttribute('data-xss-protected', 'true');
            
            // Protéger les champs de saisie
            const inputs = form.querySelectorAll('input[type="text"], input[type="email"], input[type="url"], textarea');
            inputs.forEach(input => {
                // Éviter la double protection
                if (input.hasAttribute('data-xss-protected')) return;
                
                // Sauvegarder les gestionnaires d'événements originaux
                const originalOnInput = input.oninput;
                const originalOnChange = input.onchange;
                
                // Ajouter un validateur pour l'événement input
                input.addEventListener('input', function(e) {
                    const inputType = input.type === 'email' ? 'email' : 
                                     input.type === 'url' ? 'url' : 'text';
                    const validation = validateInput(this.value, inputType);
                    
                    // Ajouter une classe visuelle pour indiquer la validité
                    if (!validation.valid) {
                        this.classList.add('invalid-input');
                        
                        // Créer ou mettre à jour un message d'erreur
                        let errorMsg = input.nextElementSibling;
                        if (!errorMsg || !errorMsg.classList.contains('error-message')) {
                            errorMsg = document.createElement('div');
                            errorMsg.classList.add('error-message');
                            input.parentNode.insertBefore(errorMsg, input.nextSibling);
                        }
                        errorMsg.textContent = validation.message;
                        errorMsg.style.color = 'red';
                        errorMsg.style.fontSize = '0.8em';
                        errorMsg.style.marginTop = '5px';
                    } else {
                        this.classList.remove('invalid-input');
                        
                        // Supprimer le message d'erreur s'il existe
                        const errorMsg = input.nextElementSibling;
                        if (errorMsg && errorMsg.classList.contains('error-message')) {
                            errorMsg.remove();
                        }
                    }
                    
                    // Appeler le gestionnaire d'événements original s'il existe
                    if (typeof originalOnInput === 'function') {
                        originalOnInput.call(this, e);
                    }
                });
                
                // Ajouter un validateur pour l'événement change
                input.addEventListener('change', function(e) {
                    const inputType = input.type === 'email' ? 'email' : 
                                     input.type === 'url' ? 'url' : 'text';
                    const validation = validateInput(this.value, inputType);
                    
                    // Si la valeur est valide mais contient des caractères à échapper
                    if (validation.valid && validation.sanitized !== this.value) {
                        this.value = validation.sanitized;
                    }
                    
                    // Appeler le gestionnaire d'événements original s'il existe
                    if (typeof originalOnChange === 'function') {
                        originalOnChange.call(this, e);
                    }
                });
                
                // Marquer le champ comme protégé
                input.setAttribute('data-xss-protected', 'true');
            });
        }
        
        // Protéger contre SQLi
        if (config.protections.sqli) {
            // Ajouter un attribut pour marquer le formulaire comme protégé contre SQLi
            form.setAttribute('data-sqli-protected', 'true');
            
            // Protéger les champs de saisie
            const inputs = form.querySelectorAll('input[type="text"], input[type="search"], textarea');
            inputs.forEach(input => {
                // Éviter la double protection
                if (input.hasAttribute('data-sqli-protected')) return;
                
                // Marquer le champ comme protégé
                input.setAttribute('data-sqli-protected', 'true');
            });
        }
        
        // Protéger contre CSRF
        if (config.protections.csrf && window.csrf) {
            // Ajouter un jeton CSRF au formulaire
            window.csrf.addCSRFTokenToForm(form);
        }
        
        // Sauvegarder le gestionnaire d'événements original
        const originalSubmit = form.onsubmit;
        
        // Remplacer le gestionnaire d'événements submit
        form.onsubmit = function(e) {
            // Valider tous les champs avant la soumission
            const inputs = this.querySelectorAll('input[type="text"], input[type="email"], input[type="url"], textarea');
            let isValid = true;
            
            inputs.forEach(input => {
                const inputType = input.type === 'email' ? 'email' : 
                                 input.type === 'url' ? 'url' : 'text';
                const validation = validateInput(input.value, inputType);
                
                if (!validation.valid) {
                    isValid = false;
                    input.classList.add('invalid-input');
                    
                    // Créer ou mettre à jour un message d'erreur
                    let errorMsg = input.nextElementSibling;
                    if (!errorMsg || !errorMsg.classList.contains('error-message')) {
                        errorMsg = document.createElement('div');
                        errorMsg.classList.add('error-message');
                        input.parentNode.insertBefore(errorMsg, input.nextSibling);
                    }
                    errorMsg.textContent = validation.message;
                    errorMsg.style.color = 'red';
                    errorMsg.style.fontSize = '0.8em';
                    errorMsg.style.marginTop = '5px';
                } else {
                    // Appliquer la valeur sanitisée
                    input.value = validation.sanitized;
                }
            });
            
            // Vérifier le jeton CSRF si la protection est activée
            if (config.protections.csrf && window.csrf) {
                const formId = form.id || 'form_' + Math.random().toString(36).substr(2, 9);
                const csrfInput = form.querySelector('input[name="csrf_token"]');
                
                if (!csrfInput || !window.csrf.validateCSRFToken(formId, csrfInput.value)) {
                    isValid = false;
                    alert('Erreur de sécurité: jeton CSRF invalide. Veuillez rafraîchir la page et réessayer.');
                    
                    // Journaliser la tentative d'attaque
                    if (window.securityLogs) {
                        window.securityLogs.addLog({
                            action: 'Tentative d\'attaque',
                            details: 'Tentative de soumission avec un jeton CSRF invalide',
                            status: window.securityLogs.LOG_TYPES.DANGER
                        });
                    }
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
        form.setAttribute('data-security-protected', 'true');
    }
    
    /**
     * Protège tous les formulaires de la page
     */
    function protectAllForms() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => protectForm(form));
    }
    
    /**
     * Protège dynamiquement les nouveaux éléments ajoutés au DOM
     */
    function setupDynamicProtection() {
        // Observer les modifications du DOM pour protéger les nouveaux formulaires
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach(node => {
                        // Protéger les nouveaux formulaires
                        if (node.nodeName === 'FORM') {
                            protectForm(node);
                        }
                        
                        // Rechercher les formulaires dans les sous-éléments
                        if (node.querySelectorAll) {
                            const forms = node.querySelectorAll('form');
                            forms.forEach(form => protectForm(form));
                        }
                    });
                }
            });
        });
        
        // Observer tout le document
        observer.observe(document.body, { childList: true, subtree: true });
    }
    
    /**
     * Initialise les protections de sécurité
     */
    function init() {
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
        
        // Protéger tous les formulaires existants
        protectAllForms();
        
        // Mettre en place la protection dynamique
        setupDynamicProtection();
        
        console.log('Protections de sécurité initialisées');
    }
    
    // Initialiser les protections lorsque le DOM est chargé
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // API publique
    return {
        escapeHtml,
        sanitizeSql,
        validateInput,
        protectForm,
        protectAllForms
    };
})();