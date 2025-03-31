// Module de protection CSRF et de gestion sécurisée des cookies

// Configuration des cookies
const cookieConfig = {
    secure: true,       // Cookies uniquement sur HTTPS
    httpOnly: true,     // Cookies inaccessibles via JavaScript
    sameSite: 'strict', // Cookies envoyés uniquement pour les requêtes provenant du même site
    maxAge: 3600000     // Durée de vie du cookie (1 heure)
};

// Vérifier si la configuration centralisée est disponible
document.addEventListener('DOMContentLoaded', function() {
    if (window.securityConfig && window.securityConfig.csrfProtection && window.securityConfig.csrfProtection.cookies) {
        // Appliquer la configuration centralisée
        Object.assign(cookieConfig, window.securityConfig.csrfProtection.cookies);
    }
});

// Stockage des jetons CSRF (dans un environnement de production, cela serait géré côté serveur)
const csrfTokens = {};

// Fonction pour générer un jeton CSRF aléatoire
function generateCSRFToken() {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('');
}

// Fonction pour définir un cookie sécurisé
function setSecureCookie(name, value, options = {}) {
    const mergedOptions = { ...cookieConfig, ...options };
    let cookieString = `${name}=${encodeURIComponent(value)}`;
    
    if (mergedOptions.maxAge) {
        cookieString += `; max-age=${mergedOptions.maxAge}`;
    }
    
    // Toujours activer l'option secure pour les cookies
    // Force l'option secure même en développement local pour une sécurité maximale
    cookieString += '; secure';
    
    // Note: httpOnly ne peut pas être défini côté client, il doit être défini côté serveur
    // L'attribut est conservé dans la configuration pour référence et doit être appliqué côté serveur
    // Pour les applications en production, configurer le serveur pour ajouter httpOnly à tous les cookies sensibles
    
    // Définir sameSite à 'strict' pour une protection maximale contre les attaques CSRF
    // Cette option empêche l'envoi du cookie lors de requêtes cross-site
    cookieString += `; samesite=strict`;
    
    // Ajouter un chemin pour s'assurer que le cookie est disponible sur tout le site
    cookieString += '; path=/';
    
    document.cookie = cookieString;
}

// Fonction pour obtenir la valeur d'un cookie
function getCookie(name) {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith(name + '=')) {
            return decodeURIComponent(cookie.substring(name.length + 1));
        }
    }
    return null;
}

// Fonction pour générer un jeton CSRF et l'ajouter à un formulaire
function addCSRFTokenToForm(form) {
    if (!form) return;
    
    // Vérifier si le formulaire a déjà été traité
    if (form.hasAttribute('data-csrf-protected')) {
        return form.querySelector('input[name="csrf_token"]')?.value;
    }
    
    // Générer un nouveau jeton
    const token = generateCSRFToken();
    
    // Stocker le jeton pour validation ultérieure
    const formId = form.id || `form_${Math.random().toString(36).substr(2, 9)}`;
    if (!form.id) form.id = formId;
    
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
    
    // Stocker également le jeton dans un cookie sécurisé
    setSecureCookie(`csrf_${formId}`, token);
    
    return token;
}

// Fonction pour valider un jeton CSRF
function validateCSRFToken(formId, token) {
    // Vérifier si le jeton existe et correspond
    const storedToken = csrfTokens[formId];
    const cookieToken = getCookie(`csrf_${formId}`);
    
    // Vérifier si les jetons existent
    if (!token || !storedToken || !cookieToken) {
        console.error('Validation CSRF échouée: jetons manquants', {
            hasToken: !!token,
            hasStoredToken: !!storedToken,
            hasCookieToken: !!cookieToken
        });
        return false;
    }
    
    // Le jeton doit correspondre à la fois au jeton stocké en mémoire et au cookie
    const isValid = token === storedToken && token === cookieToken;
    
    // Journaliser les tentatives de validation échouées
    if (!isValid && window.securityLogs) {
        const clientIP = window.ipWhitelist ? window.ipWhitelist.getClientIP() : '127.0.0.1';
        window.securityLogs.addLoginLog('système', clientIP, window.securityLogs.LOG_TYPES.SUSPICIOUS, 'Tentative de soumission avec un jeton CSRF invalide');
    }
    
    // Supprimer le jeton après validation (usage unique)
    if (isValid) {
        delete csrfTokens[formId];
        setSecureCookie(`csrf_${formId}`, '', { maxAge: -1 }); // Supprimer le cookie
    }
    
    return isValid;
}

// Fonction pour régénérer l'ID de session après connexion
function regenerateSessionId(maxAge = 3600) {
    // Générer un nouvel ID de session
    const newSessionId = generateCSRFToken();
    
    // Sauvegarder les données de session actuelles
    const sessionData = {};
    for (const key in sessionStorage) {
        if (sessionStorage.hasOwnProperty(key)) {
            sessionData[key] = sessionStorage.getItem(key);
        }
    }
    
    // Effacer la session actuelle
    sessionStorage.clear();
    
    // Restaurer les données avec le nouvel ID
    for (const key in sessionData) {
        if (sessionData.hasOwnProperty(key)) {
            sessionStorage.setItem(key, sessionData[key]);
        }
    }
    
    // Stocker le nouvel ID de session
    sessionStorage.setItem('sessionId', newSessionId);
    
    // Définir également un cookie de session sécurisé
    // Utiliser les options de sécurité maximales pour le cookie de session
    setSecureCookie('sessionId', newSessionId, {
        maxAge: maxAge,
        secure: true,
        httpOnly: true,
        sameSite: 'strict'
    });
    
    // Enregistrer la régénération dans les logs si disponible
    if (window.securityLogs) {
        const clientIP = window.ipWhitelist ? window.ipWhitelist.getClientIP() : '127.0.0.1';
        window.securityLogs.addLoginLog(sessionStorage.getItem('userEmail') || 'système', 
            clientIP, 
            window.securityLogs.LOG_TYPES.INFO, 
            'ID de session régénéré');
    }
    
    return newSessionId;
}

// Fonction pour protéger tous les formulaires d'une page
function protectForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        addCSRFTokenToForm(form);
        
        // Ajouter un écouteur d'événements pour valider le jeton lors de la soumission
        const originalSubmitEvent = form.onsubmit;
        form.onsubmit = function(e) {
            const formId = this.id;
            const csrfInput = this.querySelector('input[name="csrf_token"]');
            
            if (!csrfInput || !validateCSRFToken(formId, csrfInput.value)) {
                e.preventDefault();
                console.error('Erreur de validation CSRF');
                alert('Erreur de sécurité: jeton CSRF invalide. Veuillez rafraîchir la page et réessayer.');
                return false;
            }
            
            // Exécuter l'événement de soumission original s'il existe
            if (typeof originalSubmitEvent === 'function') {
                return originalSubmitEvent.call(this, e);
            }
        };
    });
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.csrf = {
    generateCSRFToken,
    setSecureCookie,
    getCookie,
    addCSRFTokenToForm,
    validateCSRFToken,
    regenerateSessionId,
    protectForms
};

// Initialiser la protection CSRF lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    // Protéger tous les formulaires existants
    protectForms();
    
    // Observer les changements dans le DOM pour protéger les formulaires ajoutés dynamiquement
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                // Parcourir les nœuds ajoutés
                mutation.addedNodes.forEach(function(node) {
                    // Vérifier si le nœud est un formulaire
                    if (node.tagName === 'FORM') {
                        addCSRFTokenToForm(node);
                    }
                    // Vérifier si le nœud contient des formulaires
                    if (node.querySelectorAll) {
                        const forms = node.querySelectorAll('form');
                        forms.forEach(form => addCSRFTokenToForm(form));
                    }
                });
            }
        });
    });
    
    // Observer tout le document pour les changements
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});