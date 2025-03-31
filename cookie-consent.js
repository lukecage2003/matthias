/**
 * Module de gestion des cookies pour Tech Shield
 * Ce module permet d'afficher une bannière de consentement aux cookies,
 * de collecter le consentement de l'utilisateur et de gérer les préférences.
 */

// Configuration des types de cookies
const COOKIE_TYPES = {
    NECESSARY: 'necessary',     // Cookies nécessaires au fonctionnement du site
    FUNCTIONAL: 'functional',   // Cookies fonctionnels (préférences, etc.)
    ANALYTICS: 'analytics',     // Cookies d'analyse (statistiques de visite)
    MARKETING: 'marketing'      // Cookies marketing (publicités ciblées)
};

// Configuration par défaut
const DEFAULT_CONFIG = {
    cookieName: 'tech_shield_cookie_consent',
    cookieExpiration: 180, // Durée de validité en jours
    showOnFirstVisit: true,
    position: 'bottom', // 'bottom' ou 'top'
    theme: 'dark', // 'dark' ou 'light'
    language: 'fr',
    translations: {
        fr: {
            title: 'Nous utilisons des cookies',
            description: 'Ce site utilise des cookies pour améliorer votre expérience de navigation, personnaliser le contenu et analyser notre trafic. Vous pouvez choisir les cookies que vous acceptez.',
            acceptAll: 'Tout accepter',
            rejectAll: 'Tout refuser',
            customize: 'Personnaliser',
            save: 'Enregistrer mes préférences',
            necessary: {
                title: 'Cookies nécessaires',
                description: 'Ces cookies sont indispensables au fonctionnement du site et ne peuvent pas être désactivés.'
            },
            functional: {
                title: 'Cookies fonctionnels',
                description: 'Ces cookies permettent de mémoriser vos préférences et de personnaliser votre expérience.'
            },
            analytics: {
                title: 'Cookies d\'analyse',
                description: 'Ces cookies nous aident à comprendre comment les visiteurs interagissent avec notre site.'
            },
            marketing: {
                title: 'Cookies marketing',
                description: 'Ces cookies sont utilisés pour vous proposer des publicités pertinentes.'
            },
            moreInfo: 'En savoir plus sur notre politique de confidentialité',
            closeBtn: 'Fermer'
        }
    }
};

// État du consentement
let consentState = {
    necessary: true, // Toujours activé
    functional: false,
    analytics: false,
    marketing: false
};

/**
 * Initialise le module de gestion des cookies
 * @param {Object} config - Configuration personnalisée (optionnelle)
 */
function initCookieConsent(config = {}) {
    // Fusionner la configuration par défaut avec la configuration personnalisée
    const mergedConfig = { ...DEFAULT_CONFIG, ...config };
    
    // Vérifier si l'utilisateur a déjà donné son consentement
    const savedConsent = getCookie(mergedConfig.cookieName);
    
    if (savedConsent) {
        // Restaurer les préférences sauvegardées
        try {
            consentState = JSON.parse(savedConsent);
            // Appliquer les préférences (activer/désactiver les cookies)
            applyConsent(consentState);
        } catch (error) {
            console.error('Erreur lors de la restauration des préférences de cookies:', error);
            // En cas d'erreur, réinitialiser le consentement
            resetConsent(mergedConfig);
        }
    } else if (mergedConfig.showOnFirstVisit) {
        // Afficher la bannière de consentement
        showConsentBanner(mergedConfig);
    }
    
    // Ajouter un lien dans le footer pour gérer les préférences
    addPreferencesLink(mergedConfig);
}

/**
 * Affiche la bannière de consentement
 * @param {Object} config - Configuration
 */
function showConsentBanner(config) {
    // Créer l'élément de la bannière
    const banner = document.createElement('div');
    banner.id = 'cookie-consent-banner';
    banner.className = `cookie-banner ${config.position} ${config.theme}`;
    
    // Contenu de la bannière
    const translations = config.translations[config.language];
    
    banner.innerHTML = `
        <div class="cookie-banner-content">
            <h3>${translations.title}</h3>
            <p>${translations.description}</p>
            <div class="cookie-banner-actions">
                <button id="cookie-accept-all" class="cookie-btn cookie-btn-primary">${translations.acceptAll}</button>
                <button id="cookie-reject-all" class="cookie-btn cookie-btn-secondary">${translations.rejectAll}</button>
                <button id="cookie-customize" class="cookie-btn cookie-btn-tertiary">${translations.customize}</button>
            </div>
            <div id="cookie-preferences" class="cookie-preferences" style="display: none;">
                <div class="cookie-preference-item">
                    <div>
                        <strong>${translations.necessary.title}</strong>
                        <p>${translations.necessary.description}</p>
                    </div>
                    <label class="cookie-switch">
                        <input type="checkbox" checked disabled>
                        <span class="cookie-slider"></span>
                    </label>
                </div>
                <div class="cookie-preference-item">
                    <div>
                        <strong>${translations.functional.title}</strong>
                        <p>${translations.functional.description}</p>
                    </div>
                    <label class="cookie-switch">
                        <input type="checkbox" id="cookie-functional">
                        <span class="cookie-slider"></span>
                    </label>
                </div>
                <div class="cookie-preference-item">
                    <div>
                        <strong>${translations.analytics.title}</strong>
                        <p>${translations.analytics.description}</p>
                    </div>
                    <label class="cookie-switch">
                        <input type="checkbox" id="cookie-analytics">
                        <span class="cookie-slider"></span>
                    </label>
                </div>
                <div class="cookie-preference-item">
                    <div>
                        <strong>${translations.marketing.title}</strong>
                        <p>${translations.marketing.description}</p>
                    </div>
                    <label class="cookie-switch">
                        <input type="checkbox" id="cookie-marketing">
                        <span class="cookie-slider"></span>
                    </label>
                </div>
                <div class="cookie-preferences-actions">
                    <button id="cookie-save-preferences" class="cookie-btn cookie-btn-primary">${translations.save}</button>
                </div>
            </div>
            <div class="cookie-banner-footer">
                <a href="rgpd.html" class="cookie-more-info">${translations.moreInfo}</a>
            </div>
        </div>
        <button id="cookie-close" class="cookie-close-btn">${translations.closeBtn}</button>
    `;
    
    // Ajouter la bannière au document
    document.body.appendChild(banner);
    
    // Ajouter les styles CSS
    addCookieStyles(config);
    
    // Ajouter les gestionnaires d'événements
    document.getElementById('cookie-accept-all').addEventListener('click', () => {
        acceptAllCookies(config);
    });
    
    document.getElementById('cookie-reject-all').addEventListener('click', () => {
        rejectAllCookies(config);
    });
    
    document.getElementById('cookie-customize').addEventListener('click', () => {
        togglePreferences();
    });
    
    document.getElementById('cookie-save-preferences').addEventListener('click', () => {
        savePreferences(config);
    });
    
    document.getElementById('cookie-close').addEventListener('click', () => {
        closeBanner();
    });
    
    // Initialiser les cases à cocher avec l'état actuel
    document.getElementById('cookie-functional').checked = consentState.functional;
    document.getElementById('cookie-analytics').checked = consentState.analytics;
    document.getElementById('cookie-marketing').checked = consentState.marketing;
}

/**
 * Ajoute les styles CSS pour la bannière de cookies
 * @param {Object} config - Configuration
 */
function addCookieStyles(config) {
    // Vérifier si la feuille de style est déjà chargée
    if (!document.querySelector('link[href="cookie-consent.css"]')) {
        const linkElement = document.createElement('link');
        linkElement.rel = 'stylesheet';
        linkElement.href = 'cookie-consent.css';
        document.head.appendChild(linkElement);
    }
}

/**
 * Bascule l'affichage des préférences de cookies
 */
function togglePreferences() {
    const preferencesElement = document.getElementById('cookie-preferences');
    if (preferencesElement) {
        preferencesElement.style.display = preferencesElement.style.display === 'none' ? 'block' : 'none';
    }
}

/**
 * Accepte tous les types de cookies
 * @param {Object} config - Configuration
 */
function acceptAllCookies(config) {
    consentState = {
        necessary: true,
        functional: true,
        analytics: true,
        marketing: true
    };
    
    saveConsent(consentState, config);
    closeBanner();
}

/**
 * Refuse tous les cookies sauf les nécessaires
 * @param {Object} config - Configuration
 */
function rejectAllCookies(config) {
    consentState = {
        necessary: true,
        functional: false,
        analytics: false,
        marketing: false
    };
    
    saveConsent(consentState, config);
    closeBanner();
}

/**
 * Enregistre les préférences personnalisées
 * @param {Object} config - Configuration
 */
function savePreferences(config) {
    consentState = {
        necessary: true, // Toujours activé
        functional: document.getElementById('cookie-functional').checked,
        analytics: document.getElementById('cookie-analytics').checked,
        marketing: document.getElementById('cookie-marketing').checked
    };
    
    saveConsent(consentState, config);
    closeBanner();
}

/**
 * Ferme la bannière de consentement
 */
function closeBanner() {
    const banner = document.getElementById('cookie-consent-banner');
    if (banner) {
        banner.style.display = 'none';
    }
}

/**
 * Enregistre le consentement dans un cookie
 * @param {Object} consent - État du consentement
 * @param {Object} config - Configuration
 */
function saveConsent(consent, config) {
    // Enregistrer les préférences dans un cookie
    setCookie(config.cookieName, JSON.stringify(consent), config.cookieExpiration);
    
    // Appliquer les préférences
    applyConsent(consent);
}

/**
 * Applique les préférences de consentement
 * @param {Object} consent - État du consentement
 */
function applyConsent(consent) {
    // Activer/désactiver les cookies en fonction des préférences
    if (consent.functional) {
        enableFunctionalCookies();
    } else {
        disableFunctionalCookies();
    }
    
    if (consent.analytics) {
        enableAnalyticsCookies();
    } else {
        disableAnalyticsCookies();
    }
    
    if (consent.marketing) {
        enableMarketingCookies();
    } else {
        disableMarketingCookies();
    }
    
    // Déclencher un événement pour informer les autres scripts
    const event = new CustomEvent('cookieConsentUpdated', { detail: consent });
    document.dispatchEvent(event);
}

/**
 * Réinitialise le consentement
 * @param {Object} config - Configuration
 */
function resetConsent(config) {
    // Réinitialiser l'état du consentement
    consentState = {
        necessary: true,
        functional: false,
        analytics: false,
        marketing: false
    };
    
    // Supprimer le cookie de consentement
    deleteCookie(config.cookieName);
    
    // Afficher la bannière
    showConsentBanner(config);
}

/**
 * Ajoute un lien dans le footer pour gérer les préférences de cookies
 * @param {Object} config - Configuration
 */
function addPreferencesLink(config) {
    const footer = document.querySelector('footer');
    if (footer) {
        const translations = config.translations[config.language];
        const preferencesLink = document.createElement('span');
        preferencesLink.className = 'cookie-preferences-link';
        preferencesLink.textContent = 'Gérer mes cookies';
        preferencesLink.addEventListener('click', () => {
            // Afficher la bannière de consentement
            if (document.getElementById('cookie-consent-banner')) {
                document.getElementById('cookie-consent-banner').style.display = 'block';
                togglePreferences();
            } else {
                showConsentBanner(config);
                togglePreferences();
            }
        });
        
        footer.appendChild(preferencesLink);
    }
}

/**
 * Définit un cookie
 * @param {string} name - Nom du cookie
 * @param {string} value - Valeur du cookie
 * @param {number} days - Durée de validité en jours
 */
function setCookie(name, value, days) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = "expires=" + date.toUTCString();
    document.cookie = name + "=" + value + ";" + expires + ";path=/;SameSite=Lax";
}

/**
 * Récupère la valeur d'un cookie
 * @param {string} name - Nom du cookie
 * @returns {string|null} - Valeur du cookie ou null si non trouvé
 */
function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') {
            c = c.substring(1, c.length);
        }
        if (c.indexOf(nameEQ) === 0) {
            return c.substring(nameEQ.length, c.length);
        }
    }
    return null;
}

/**
 * Supprime un cookie
 * @param {string} name - Nom du cookie
 */
function deleteCookie(name) {
    document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:01 GMT;path=/;SameSite=Lax';
}

/**
 * Active les cookies fonctionnels
 */
function enableFunctionalCookies() {
    // Implémentation spécifique pour activer les cookies fonctionnels
    console.log('Cookies fonctionnels activés');
}

/**
 * Désactive les cookies fonctionnels
 */
function disableFunctionalCookies() {
    // Implémentation spécifique pour désactiver les cookies fonctionnels
    console.log('Cookies fonctionnels désactivés');
}

/**
 * Active les cookies d'analyse
 */
function enableAnalyticsCookies() {
    // Implémentation spécifique pour activer les cookies d'analyse
    console.log('Cookies d\'analyse activés');
    
    // Exemple pour Google Analytics
    if (window.ga) {
        window['ga-disable-UA-XXXXXXXX-X'] = false;
    }
}

/**
 * Désactive les cookies d'analyse
 */
function disableAnalyticsCookies() {
    // Implémentation spécifique pour désactiver les cookies d'analyse
    console.log('Cookies d\'analyse désactivés');
    
    // Exemple pour Google Analytics
    window['ga-disable-UA-XXXXXXXX-X'] = true;
    
    // Supprimer les cookies d'analyse existants
    deleteCookie('_ga');
    deleteCookie('_gat');
    deleteCookie('_gid');
}

/**
 * Active les cookies marketing
 */
function enableMarketingCookies() {
    // Implémentation spécifique pour activer les cookies marketing
    console.log('Cookies marketing activés');
}

/**
 * Désactive les cookies marketing
 */
function disableMarketingCookies() {
    // Implémentation spécifique pour désactiver les cookies marketing
    console.log('Cookies marketing désactivés');
}

// Exporter les fonctions pour une utilisation externe
window.cookieConsent = {
    init: initCookieConsent,
    accept: acceptAllCookies,
    reject: rejectAllCookies,
    reset: resetConsent,
    getState: () => ({ ...consentState }),
    COOKIE_TYPES
};

// Initialiser automatiquement le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', () => {
    initCookieConsent();
});