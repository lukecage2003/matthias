/**
 * Module de protection contre les attaques CSRF pour Tech Shield
 * Ce module fournit des fonctions robustes pour générer, valider et gérer les jetons CSRF
 * pour tous les formulaires du site
 */

window.csrfProtection = (function() {
    // Configuration des protections CSRF
    const config = {
        // Durée de validité des jetons en secondes (1 heure par défaut)
        tokenValiditySeconds: 3600,
        
        // Préfixe pour les jetons CSRF
        tokenPrefix: 'tech-shield-csrf-',
        
        // Options pour les cookies
        cookieOptions: {
            // Durée de vie du cookie en secondes
            maxAge: 3600,
            
            // Restreindre le cookie au protocole HTTPS
            secure: location.protocol === 'https:',
            
            // Empêcher l'accès au cookie via JavaScript
            httpOnly: true,
            
            // Restreindre le cookie au domaine actuel
            sameSite: 'strict',
            
            // Chemin du cookie
            path: '/'
        }
    };
    
    // Stockage des jetons CSRF (dans un environnement de production, cela serait géré côté serveur)
    const csrfTokens = {};
    
    /**
     * Génère un jeton CSRF aléatoire et sécurisé
     * @returns {string} - Jeton CSRF
     */
    function generateCSRFToken() {
        // Générer un jeton aléatoire
        const randomPart = Math.random().toString(36).substring(2, 15);
        const timePart = Date.now().toString(36);
        const token = config.tokenPrefix + randomPart + timePart;
        
        return token;
    }
    
    /**
     * Définit un cookie sécurisé
     * @param {string} name - Nom du cookie
     * @param {string} value - Valeur du cookie
     * @param {Object} options - Options du cookie
     */
    function setSecureCookie(name, value, options = {}) {
        // Fusionner les options par défaut avec les options fournies
        const cookieOptions = { ...config.cookieOptions, ...options };
        
        // Construire la chaîne de cookie
        let cookieString = `${name}=${value}`;
        
        // Ajouter les options
        if (cookieOptions.maxAge) {
            cookieString += `; max-age=${cookieOptions.maxAge}`;
        }
        
        if (cookieOptions.path) {
            cookieString += `; path=${cookieOptions.path}`;
        }
        
        if (cookieOptions.domain) {
            cookieString += `; domain=${cookieOptions.domain}`;
        }
        
        if (cookieOptions.secure) {
            cookieString += '; secure';
        }
        
        if (cookieOptions.httpOnly) {
            cookieString += '; httponly';
        }
        
        // Définir sameSite à 'strict' pour une protection maximale contre les attaques CSRF
        cookieString += `; samesite=${cookieOptions.sameSite || 'strict'}`;
        
        // Définir le cookie
        document.cookie = cookieString;
    }
    
    /**
     * Récupère la valeur d'un cookie
     * @param {string} name - Nom du cookie
     * @returns {string|null} - Valeur du cookie ou null si non trouvé
     */
    function getCookie(name) {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.startsWith(name + '=')) {
                return cookie.substring(name.length + 1);
            }
        }
        return null;
    }
    
    /**
     * Génère un jeton CSRF et l'ajoute à un formulaire
     * @param {HTMLFormElement} form - Formulaire à protéger
     * @returns {string} - Jeton CSRF généré
     */
    function addCSRFTokenToForm(form) {
        if (!form || !(form instanceof HTMLFormElement)) return null;
        
        // Éviter la double protection
        if (form.hasAttribute('data-csrf-protected')) {
            return form.querySelector('input[name="csrf_token"]')?.value;
        }
        
        // Générer un ID unique pour le formulaire s'il n'en a pas
        const formId = form.id || 'form_' + Math.random().toString(36).substr(2, 9);
        if (!form.id) form.id = formId;
        
        // Générer un nouveau jeton CSRF
        const token = generateCSRFToken();
        
        // Stocker le jeton
        csrfTokens[formId] = token;
        
        // Ajouter le jeton au formulaire
        let csrfInput = form.querySelector('input[name="csrf_token"]');
        
        if (!csrfInput) {
            csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            form.appendChild(csrfInput);
        }
        
        csrfInput.value = token;
        
        // Marquer le formulaire comme protégé
        form.setAttribute('data-csrf-protected', 'true');
        
        // Stocker le jeton dans un cookie pour la validation côté serveur
        setSecureCookie(`csrf_${formId}`, token);
        
        return token;
    }
    
    /**
     * Valide un jeton CSRF
     * @param {string} formId - ID du formulaire
     * @param {string} token - Jeton CSRF à valider
     * @returns {boolean} - true si le jeton est valide, false sinon
     */
    function validateCSRFToken(formId, token) {
        // Vérifier que le jeton existe
        const storedToken = csrfTokens[formId];
        const cookieToken = getCookie(`csrf_${formId}`);
        
        // Vérifier que tous les jetons sont présents
        if (!token || !storedToken || !cookieToken) {
            console.error('Validation CSRF échouée: jetons manquants', {
                hasToken: !!token,
                hasStoredToken: !!storedToken,
                hasCookieToken: !!cookieToken
            });
            return false;
        }
        
        // Vérifier que les jetons correspondent
        const isValid = token === storedToken && token === cookieToken;
        
        // Journaliser les tentatives d'attaque
        if (!isValid && window.securityLogs) {
            const clientIP = window.securityLogs.getClientIP() || 'inconnue';
            window.securityLogs.addLog({
                action: 'Tentative d\'attaque',
                details: 'Tentative de soumission avec un jeton CSRF invalide',
                status: window.securityLogs.LOG_TYPES.DANGER,
                ip: clientIP
            });
        }
        
        // Supprimer le jeton après validation (usage unique)
        if (isValid) {
            delete csrfTokens[formId];
            setSecureCookie(`csrf_${formId}`, '', { maxAge: -1 }); // Supprimer le cookie
        }
        
        return isValid;
    }
    
    /**
     * Régénère l'ID de session pour prévenir les attaques de fixation de session
     */
    function regenerateSessionId() {
        // Dans un environnement de production, cela serait géré côté serveur
        // Ici, nous simulons une régénération d'ID de session
        const newSessionId = generateCSRFToken();
        setSecureCookie('session_id', newSessionId);
        
        // Invalider tous les jetons CSRF existants
        for (const formId in csrfTokens) {
            delete csrfTokens[formId];
            setSecureCookie(`csrf_${formId}`, '', { maxAge: -1 });
        }
        
        console.log('ID de session régénéré');
    }
    
    /**
     * Protège un formulaire contre les attaques CSRF
     * @param {HTMLFormElement} form - Formulaire à protéger
     */
    function protectForm(form) {
        if (!form || !(form instanceof HTMLFormElement)) return;
        
        // Éviter la double protection
        if (form.hasAttribute('data-csrf-form-protected')) return;
        
        // Ajouter un jeton CSRF au formulaire
        addCSRFTokenToForm(form);
        
        // Sauvegarder le gestionnaire d'événements original
        const originalSubmit = form.onsubmit;
        
        // Remplacer le gestionnaire d'événements submit
        form.onsubmit = function(e) {
            // Vérifier le jeton CSRF
            const formId = this.id || 'form_' + Math.random().toString(36).substr(2, 9);
            const csrfInput = this.querySelector('input[name="csrf_token"]');
            
            if (!csrfInput || !validateCSRFToken(formId, csrfInput.value)) {
                e.preventDefault();
                console.error('Erreur de validation CSRF');
                alert('Erreur de sécurité: jeton CSRF invalide. Veuillez rafraîchir la page et réessayer.');
                return false;
            }
            
            // Appeler le gestionnaire d'événements original s'il existe
            if (typeof originalSubmit === 'function') {
                return originalSubmit.call(this, e);
            }
        };
        
        // Marquer le formulaire comme protégé
        form.setAttribute('data-csrf-form-protected', 'true');
    }
    
    /**
     * Protège tous les formulaires de la page contre les attaques CSRF
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
                            addCSRFTokenToForm(node);
                        }
                        
                        // Rechercher les formulaires dans les sous-éléments
                        if (node.querySelectorAll) {
                            const forms = node.querySelectorAll('form');
                            forms.forEach(form => addCSRFTokenToForm(form));
                        }
                    });
                }
            });
        });
        
        // Observer tout le document
        observer.observe(document.body, { childList: true, subtree: true });
    }
    
    /**
     * Initialise les protections CSRF
     */
    function init() {
        // Protéger tous les formulaires existants
        protectAllForms();
        
        // Mettre en place la protection dynamique
        setupDynamicProtection();
        
        console.log('Protection CSRF initialisée');
    }
    
    // Initialiser les protections lorsque le DOM est chargé
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // API publique
    return {
        generateCSRFToken,
        addCSRFTokenToForm,
        validateCSRFToken,
        regenerateSessionId,
        protectForm,
        protectAllForms
    };
})();