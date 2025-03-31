/**
 * Module de protection contre les attaques XSS pour Tech Shield
 * Ce module fournit des fonctions robustes pour échapper les caractères HTML spéciaux
 * et protéger contre les attaques XSS dans les formulaires et l'affichage des données
 */

window.xssProtection = (function() {
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
     * Valide une entrée utilisateur pour détecter les tentatives d'injection XSS
     * @param {string} input - Entrée à valider
     * @returns {Object} - Résultat de la validation {valid: boolean, sanitized: string, message: string}
     */
    function validateInput(input) {
        if (input === undefined || input === null) {
            return { valid: false, sanitized: '', message: 'Entrée invalide' };
        }
        
        const inputStr = String(input).trim();
        let valid = true;
        let message = '';
        
        // Détecter les tentatives d'injection XSS
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /on\w+\s*=/gi,
            /javascript:/gi,
            /data:\s*[^\s]+\s*;/gi,
            /expression\s*\([^)]*\)/gi,
            /url\s*\([^)]*\)/gi
        ];
        
        const containsXSS = xssPatterns.some(pattern => pattern.test(inputStr));
        
        if (containsXSS) {
            valid = false;
            message = 'Contenu potentiellement dangereux détecté';
            
            // Journaliser la tentative d'attaque
            if (window.securityLogs) {
                window.securityLogs.addLog({
                    action: 'Tentative d\'attaque',
                    details: `Tentative d'injection XSS détectée: ${escapeHtml(inputStr)}`,
                    status: window.securityLogs.LOG_TYPES.DANGER
                });
            }
        }
        
        // Échapper le HTML dans tous les cas
        const sanitized = escapeHtml(inputStr);
        
        return { valid, sanitized, message };
    }
    
    /**
     * Protège un élément de formulaire contre les attaques XSS
     * @param {HTMLElement} element - Élément à protéger
     */
    function protectElement(element) {
        if (!element || !(element instanceof HTMLElement)) return;
        
        // Éviter la double protection
        if (element.hasAttribute('data-xss-protected')) return;
        
        // Sauvegarder les gestionnaires d'événements originaux
        const originalOnInput = element.oninput;
        const originalOnChange = element.onchange;
        
        // Ajouter un validateur pour l'événement input
        element.addEventListener('input', function(e) {
            const validation = validateInput(this.value);
            
            // Ajouter une classe visuelle pour indiquer la validité
            if (!validation.valid) {
                this.classList.add('invalid-input');
                
                // Créer ou mettre à jour un message d'erreur
                let errorMsg = element.nextElementSibling;
                if (!errorMsg || !errorMsg.classList.contains('error-message')) {
                    errorMsg = document.createElement('div');
                    errorMsg.classList.add('error-message');
                    element.parentNode.insertBefore(errorMsg, element.nextSibling);
                }
                errorMsg.textContent = validation.message;
                errorMsg.style.color = 'red';
                errorMsg.style.fontSize = '0.8em';
                errorMsg.style.marginTop = '5px';
            } else {
                this.classList.remove('invalid-input');
                
                // Supprimer le message d'erreur s'il existe
                const errorMsg = element.nextElementSibling;
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
        element.addEventListener('change', function(e) {
            const validation = validateInput(this.value);
            
            // Si la valeur est valide mais contient des caractères à échapper
            if (validation.valid && validation.sanitized !== this.value) {
                this.value = validation.sanitized;
            }
            
            // Appeler le gestionnaire d'événements original s'il existe
            if (typeof originalOnChange === 'function') {
                originalOnChange.call(this, e);
            }
        });
        
        // Marquer l'élément comme protégé
        element.setAttribute('data-xss-protected', 'true');
    }
    
    /**
     * Protège un formulaire contre les attaques XSS
     * @param {HTMLFormElement} form - Formulaire à protéger
     */
    function protectForm(form) {
        if (!form || !(form instanceof HTMLFormElement)) return;
        
        // Éviter la double protection
        if (form.hasAttribute('data-xss-form-protected')) return;
        
        // Protéger les champs de saisie
        const inputs = form.querySelectorAll('input[type="text"], input[type="email"], input[type="url"], textarea');
        inputs.forEach(input => protectElement(input));
        
        // Sauvegarder le gestionnaire d'événements original
        const originalSubmit = form.onsubmit;
        
        // Remplacer le gestionnaire d'événements submit
        form.onsubmit = function(e) {
            // Valider tous les champs avant la soumission
            const inputs = this.querySelectorAll('input[type="text"], input[type="email"], input[type="url"], textarea');
            let isValid = true;
            
            inputs.forEach(input => {
                const validation = validateInput(input.value);
                
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
        form.setAttribute('data-xss-form-protected', 'true');
    }
    
    /**
     * Protège tous les formulaires de la page contre les attaques XSS
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
     * Initialise les protections XSS
     */
    function init() {
        // Ajouter la méthode d'échappement au prototype String si elle n'existe pas déjà
        if (!String.prototype.escapeHtml) {
            String.prototype.escapeHtml = function() {
                return escapeHtml(this);
            };
        }
        
        // Protéger tous les formulaires existants
        protectAllForms();
        
        // Mettre en place la protection dynamique
        setupDynamicProtection();
        
        console.log('Protection XSS initialisée');
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
        validateInput,
        protectElement,
        protectForm,
        protectAllForms
    };
})();