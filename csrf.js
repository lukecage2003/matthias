// Module de protection CSRF et de gestion sécurisée des cookies

// Configuration des cookies
const cookieConfig = {
    secure: true,       // Cookies uniquement sur HTTPS
    httpOnly: true,     // Cookies inaccessibles via JavaScript
    sameSite: 'strict', // Cookies envoyés uniquement pour les requêtes provenant du même site
    maxAge: 3600000     // Durée de vie du cookie (1 heure)
};

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
    
    if (mergedOptions.secure) {
        cookieString += '; secure';
    }
    
    if (mergedOptions.httpOnly) {
        cookieString += '; httpOnly';
    }
    
    if (mergedOptions.sameSite) {
        cookieString += `; samesite=${mergedOptions.sameSite}`;
    }
    
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
    
    // Stocker également le jeton dans un cookie sécurisé
    setSecureCookie(`csrf_${formId}`, token);
    
    return token;
}

// Fonction pour valider un jeton CSRF
function validateCSRFToken(formId, token) {
    // Vérifier si le jeton existe et correspond
    const storedToken = csrfTokens[formId];
    const cookieToken = getCookie(`csrf_${formId}`);
    
    // Le jeton doit correspondre à la fois au jeton stocké en mémoire et au cookie
    const isValid = storedToken && cookieToken && token === storedToken && token === cookieToken;
    
    // Supprimer le jeton après validation (usage unique)
    if (isValid) {
        delete csrfTokens[formId];
        setSecureCookie(`csrf_${formId}`, '', { maxAge: -1 }); // Supprimer le cookie
    }
    
    return isValid;
}

// Fonction pour régénérer l'ID de session après connexion
function regenerateSessionId() {
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
    setSecureCookie('sessionId', newSessionId);
    
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
});