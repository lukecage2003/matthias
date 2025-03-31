/**
 * Module de protection contre les injections SQL pour Tech Shield
 * Ce module fournit des fonctions robustes pour valider et assainir les entrées utilisateur
 * avant qu'elles ne soient utilisées dans des requêtes SQL
 * Il gère également la capture des messages du formulaire de contact
 */

window.sqlProtection = (function() {
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
     * Valide une entrée utilisateur pour détecter les tentatives d'injection SQL
     * @param {string} input - Entrée à valider
     * @returns {Object} - Résultat de la validation {valid: boolean, sanitized: string, message: string}
     */
    function validateSqlInput(input) {
        if (input === undefined || input === null) {
            return { valid: false, sanitized: '', message: 'Entrée invalide: La valeur ne peut pas être vide ou null. Veuillez fournir une valeur valide.' };
        }
        
        const inputStr = String(input).trim();
        let valid = true;
        let message = '';
        
        // Détecter les tentatives d'injection SQL
        const sqlPatterns = [
            /('(''|[^'])*')/gi,
            /(;\s*SELECT)/gi,
            /(;\s*INSERT)/gi,
            /(;\s*UPDATE)/gi,
            /(;\s*DELETE)/gi,
            /(;\s*DROP)/gi,
            /(\/\*[\s\S]*?\*\/)/gi,
            /(--)/gi,
            /(#)/gi,
            /(\bOR\b\s+\b\w+\b\s*=\s*\w+)/gi,
            /(\bUNION\b\s+\b(ALL|SELECT)\b)/gi
        ];
        
        const containsSQL = sqlPatterns.some(pattern => pattern.test(inputStr));
        
        if (containsSQL) {
            valid = false;
            message = 'Alerte de sécurité: Caractères SQL potentiellement dangereux détectés. Veuillez éviter d\'utiliser des caractères spéciaux ou des mots-clés SQL dans votre saisie.';
            
            // Journaliser la tentative d'attaque
            if (window.securityLogs) {
                window.securityLogs.addLog({
                    action: 'Tentative d\'attaque',
                    details: `Tentative d'injection SQL détectée: ${inputStr.replace(/</g, "&lt;").replace(/>/g, "&gt;")}`,
                    status: window.securityLogs.LOG_TYPES.DANGER
                });
            }
        }
        
        // Échapper le SQL dans tous les cas
        const sanitized = sanitizeSql(inputStr);
        
        return { valid, sanitized, message };
    }
    
    /**
     * Protège un élément de formulaire contre les injections SQL
     * @param {HTMLElement} element - Élément à protéger
     */
    function protectElement(element) {
        if (!element || !(element instanceof HTMLElement)) return;
        
        // Éviter la double protection
        if (element.hasAttribute('data-sqli-protected')) return;
        
        // Sauvegarder les gestionnaires d'événements originaux
        const originalOnInput = element.oninput;
        const originalOnChange = element.onchange;
        
        // Ajouter un validateur pour l'événement input
        element.addEventListener('input', function(e) {
            const validation = validateSqlInput(this.value);
            
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
            const validation = validateSqlInput(this.value);
            
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
        element.setAttribute('data-sqli-protected', 'true');
    }
    
    /**
     * Protège un formulaire contre les injections SQL
     * @param {HTMLFormElement} form - Formulaire à protéger
     */
    function protectForm(form) {
        if (!form || !(form instanceof HTMLFormElement)) return;
        
        // Éviter la double protection
        if (form.hasAttribute('data-sqli-form-protected')) return;
        
        // Protéger les champs de saisie
        const inputs = form.querySelectorAll('input[type="text"], input[type="search"], textarea');
        inputs.forEach(input => protectElement(input));
        
        // Sauvegarder le gestionnaire d'événements original
        const originalSubmit = form.onsubmit;
        
        // Remplacer le gestionnaire d'événements submit
        form.onsubmit = function(e) {
            // Valider tous les champs avant la soumission
            const inputs = this.querySelectorAll('input[type="text"], input[type="search"], textarea');
            let isValid = true;
            
            inputs.forEach(input => {
                const validation = validateSqlInput(input.value);
                
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
        form.setAttribute('data-sqli-form-protected', 'true');
    }
    
    /**
     * Protège tous les formulaires de la page contre les injections SQL
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
                            
                            // Vérifier si le formulaire de contact a été ajouté
                            if (node.querySelector && node.querySelector('#contact-form form')) {
                                captureContactForm();
                            }
                        }
                        
                        // Vérifier si c'est le formulaire de contact
                        if (node.id === 'contact-form' || (node.querySelector && node.querySelector('#contact-form'))) {
                            captureContactForm();
                        }
                    });
                }
            });
        });
        
        // Observer tout le document
        observer.observe(document.body, { childList: true, subtree: true });
    }
    
    /**
     * Crée une fonction de préparation de requête sécurisée
     * @param {string} query - Requête SQL avec placeholders (? ou :param)
     * @param {Array|Object} params - Paramètres pour la requête
     * @returns {string} - Requête SQL sécurisée
     */
    function prepareQuery(query, params) {
        if (!query) return '';
        
        let preparedQuery = query;
        
        if (Array.isArray(params)) {
            // Remplacer les ? par les valeurs échappées
            params.forEach(param => {
                preparedQuery = preparedQuery.replace('?', sanitizeSql(param));
            });
        } else if (typeof params === 'object') {
            // Remplacer les :param par les valeurs échappées
            for (const key in params) {
                const regex = new RegExp(':' + key, 'g');
                preparedQuery = preparedQuery.replace(regex, sanitizeSql(params[key]));
            }
        }
        
        return preparedQuery;
    }
    
    /**
     * Initialise les protections SQL
     */
    function init() {
        // Ajouter la méthode d'échappement au prototype String si elle n'existe pas déjà
        if (!String.prototype.sanitizeSql) {
            String.prototype.sanitizeSql = function() {
                return sanitizeSql(this);
            };
        }
        
        // Protéger tous les formulaires existants
        protectAllForms();
        
        // Mettre en place la protection dynamique
        setupDynamicProtection();
        
        // Activer la capture du formulaire de contact
        captureContactForm();
        
        console.log('Protection SQL initialisée');
    }
    
    // Fonction pour capturer les messages du formulaire de contact
    function captureContactForm() {
        const contactForm = document.querySelector('#contact-form form');
        if (!contactForm) return;
        
        // Éviter la double capture
        if (contactForm.hasAttribute('data-capture-enabled')) return;
        
        // Sauvegarder le gestionnaire d'événements original
        const originalSubmit = contactForm.onsubmit;
        
        // Remplacer le gestionnaire d'événements submit
        contactForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            // Récupérer les valeurs du formulaire
            const nameInput = this.querySelector('#name');
            const emailInput = this.querySelector('#email');
            const messageInput = this.querySelector('#message');
            
            if (!nameInput || !emailInput || !messageInput) {
                return originalSubmit ? originalSubmit.call(this, e) : true;
            }
            
            const name = nameInput.value.trim();
            const email = emailInput.value.trim();
            const message = messageInput.value.trim();
            
            // Valider les entrées
            const nameValidation = validateSqlInput(name);
            const emailValidation = validateSqlInput(email);
            const messageValidation = validateSqlInput(message);
            
            if (!nameValidation.valid || !emailValidation.valid || !messageValidation.valid) {
                alert('Veuillez vérifier vos informations. Certains caractères ne sont pas autorisés.');
                return false;
            }
            
            try {
                // Préparer le message formaté
                const formattedMessage = `De: ${nameValidation.sanitized}\nEmail: ${emailValidation.sanitized}\nMessage: ${messageValidation.sanitized}`;
                
                // Enregistrer le message dans la base de données si disponible
                if (window.database && window.database.addMessage) {
                    const result = await window.database.addMessage(emailValidation.sanitized, formattedMessage);
                    
                    if (result.success) {
                        // Journaliser la réussite
                        if (window.securityLogs) {
                            window.securityLogs.addLog({
                                action: 'Message envoyé',
                                details: `Message envoyé par ${emailValidation.sanitized}`,
                                status: window.securityLogs.LOG_TYPES.SUCCESS
                            });
                        }
                        
                        // Réinitialiser le formulaire
                        this.reset();
                        
                        // Afficher un message de confirmation
                        alert('Votre message a été envoyé avec succès!');
                        return false;
                    }
                }
                
                // Si la base de données n'est pas disponible ou en cas d'échec, continuer avec le comportement par défaut
                return originalSubmit ? originalSubmit.call(this, e) : true;
            } catch (error) {
                console.error('Erreur lors de l\'envoi du message:', error);
                
                // Journaliser l'erreur
                if (window.securityLogs) {
                    window.securityLogs.addLog({
                        action: 'Erreur',
                        details: `Erreur d'envoi de message: ${error.message}`,
                        status: window.securityLogs.LOG_TYPES.ERROR
                    });
                }
                
                alert('Une erreur est survenue lors de l\'envoi du message. Veuillez réessayer plus tard.');
                return false;
            }
        });
        
        // Marquer le formulaire comme capturé
        contactForm.setAttribute('data-capture-enabled', 'true');
    }
    
    // Initialiser les protections lorsque le DOM est chargé
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // API publique
    return {
        sanitizeSql,
        validateSqlInput,
        protectElement,
        protectForm,
        protectAllForms,
        prepareQuery,
        captureContactForm
    };
})();