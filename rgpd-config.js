// Configuration RGPD pour Tech Shield

/**
 * Configuration des paramètres RGPD
 */
const rgpdConfig = {
    // Informations sur le responsable du traitement
    controller: {
        name: "Tech Shield",
        email: "privacy@techshield.com",
        address: "10 rue de la Technologie, 75000 Paris"
    },
    
    // Durées de conservation des données
    retention: {
        account: 1095, // 3 ans en jours
        cv: 730,       // 2 ans en jours
        logs: 365,     // 1 an en jours
        messages: 1095 // 3 ans en jours
    },
    
    // Configuration des données à anonymiser
    anonymization: {
        // Champs à anonymiser dans les logs
        logs: {
            email: { type: 'email', method: 'partial' },
            ipAddress: { type: 'ip', method: 'partial' },
            userAgent: { type: 'id', method: 'hash' }
        },
        
        // Champs à anonymiser dans les messages
        messages: {
            email: { type: 'email', method: 'partial' },
            content: { type: 'id', method: 'tokenize' }
        },
        
        // Champs à anonymiser dans les données utilisateur
        users: {
            email: { type: 'email', method: 'pseudonymize' },
            name: { type: 'name', method: 'partial' }
        }
    },
    
    // Configuration des demandes de suppression
    deletionRequests: {
        verificationRequired: true,
        processingDelay: 30, // jours
        notificationEmail: true
    },
    
    // Configuration du consentement
    consent: {
        required: true,
        expiration: 365, // jours
        categories: [
            { id: 'essential', name: 'Essentiels', required: true },
            { id: 'functional', name: 'Fonctionnels', required: false },
            { id: 'analytics', name: 'Analytiques', required: false },
            { id: 'marketing', name: 'Marketing', required: false }
        ]
    }
};

/**
 * Initialise la configuration RGPD
 */
function initRGPDConfig() {
    // Vérifier si le module d'anonymisation est disponible
    if (window.dataAnonymizer) {
        console.log('Module d\'anonymisation détecté, configuration RGPD initialisée');
        window.dataAnonymizer.init();
    } else {
        console.warn('Module d\'anonymisation non détecté, certaines fonctionnalités RGPD peuvent être limitées');
    }
    
    // Journaliser l'initialisation si le module de logs est disponible
    if (window.securityLogs) {
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: 'Configuration RGPD initialisée',
            source: 'rgpd-config'
        });
    }
    
    return true;
}

/**
 * Vérifie si une donnée doit être conservée ou supprimée en fonction de sa date
 * @param {string} date - La date de création de la donnée
 * @param {string} dataType - Le type de donnée (account, cv, logs, messages)
 * @returns {boolean} - Indique si la donnée doit être conservée
 */
function shouldRetainData(date, dataType) {
    if (!date || !dataType) return false;
    
    const creationDate = new Date(date);
    const now = new Date();
    
    // Calculer la différence en jours
    const diffTime = Math.abs(now - creationDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    // Vérifier si la période de rétention est dépassée
    const retentionPeriod = rgpdConfig.retention[dataType];
    if (!retentionPeriod) return false;
    
    return diffDays <= retentionPeriod;
}

/**
 * Anonymise les données selon la configuration RGPD
 * @param {Object} data - Les données à anonymiser
 * @param {string} dataType - Le type de données (logs, messages, users)
 * @returns {Object} - Les données anonymisées
 */
function anonymizeDataPerConfig(data, dataType) {
    if (!data || !dataType || !window.dataAnonymizer) return data;
    
    const fieldMappings = rgpdConfig.anonymization[dataType];
    if (!fieldMappings) return data;
    
    return window.dataAnonymizer.anonymizeObject(data, fieldMappings);
}

/**
 * Anonymise un tableau de données selon la configuration RGPD
 * @param {Array} dataArray - Le tableau de données à anonymiser
 * @param {string} dataType - Le type de données (logs, messages, users)
 * @returns {Array} - Le tableau de données anonymisées
 */
function anonymizeArrayPerConfig(dataArray, dataType) {
    if (!dataArray || !Array.isArray(dataArray) || !dataType || !window.dataAnonymizer) return dataArray;
    
    const fieldMappings = rgpdConfig.anonymization[dataType];
    if (!fieldMappings) return dataArray;
    
    return window.dataAnonymizer.anonymizeDataArray(dataArray, fieldMappings);
}

/**
 * Vérifie si le consentement est requis pour une catégorie
 * @param {string} category - L'identifiant de la catégorie
 * @returns {boolean} - Indique si le consentement est requis
 */
function isConsentRequired(category) {
    if (!category) return false;
    
    const categoryConfig = rgpdConfig.consent.categories.find(c => c.id === category);
    return categoryConfig ? categoryConfig.required : false;
}

/**
 * Obtient la durée de conservation pour un type de données
 * @param {string} dataType - Le type de données
 * @returns {number} - La durée de conservation en jours
 */
function getRetentionPeriod(dataType) {
    return rgpdConfig.retention[dataType] || 0;
}

// Exposer les fonctions publiques
window.rgpdConfig = {
    config: rgpdConfig,
    init: initRGPDConfig,
    shouldRetainData,
    anonymizeDataPerConfig,
    anonymizeArrayPerConfig,
    isConsentRequired,
    getRetentionPeriod
};