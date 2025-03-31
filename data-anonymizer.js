// Module d'anonymisation des données pour Tech Shield
// Implémentation des fonctionnalités de pseudonymisation et d'anonymisation des données sensibles

/**
 * Configuration du module d'anonymisation
 */
const anonymizationConfig = {
    // Types de données à anonymiser
    dataTypes: {
        EMAIL: 'email',
        IP: 'ip',
        NAME: 'name',
        PHONE: 'phone',
        ADDRESS: 'address',
        ID: 'id'
    },
    
    // Méthodes d'anonymisation
    methods: {
        HASH: 'hash',           // Hachage complet (non réversible)
        PSEUDONYMIZE: 'pseudo',  // Pseudonymisation (potentiellement réversible avec une clé)
        PARTIAL: 'partial',      // Masquage partiel (ex: j***@example.com)
        TOKENIZE: 'token'        // Remplacement par un jeton
    },
    
    // Paramètres de conservation
    retention: {
        // Durée de conservation des données originales en jours (0 = pas de conservation)
        originalData: 0,
        // Durée de conservation des données pseudonymisées en jours (0 = indéfini)
        pseudonymizedData: 365
    }
};

// Stockage des mappings de pseudonymisation (dans un environnement de production, cela serait stocké de manière sécurisée)
let pseudonymizationMappings = {};

/**
 * Initialise le module d'anonymisation
 * @returns {boolean} - Succès de l'initialisation
 */
function initAnonymizer() {
    try {
        // Charger les mappings existants
        loadMappings();
        
        // Journaliser l'initialisation si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: 'Module d\'anonymisation initialisé',
                source: 'data-anonymizer'
            });
        }
        
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'initialisation du module d\'anonymisation:', error);
        return false;
    }
}

/**
 * Charge les mappings de pseudonymisation depuis le stockage local
 */
function loadMappings() {
    const storedMappings = localStorage.getItem('pseudonymizationMappings');
    if (storedMappings) {
        try {
            pseudonymizationMappings = JSON.parse(storedMappings);
        } catch (error) {
            console.error('Erreur lors du chargement des mappings de pseudonymisation:', error);
            pseudonymizationMappings = {};
        }
    }
}

/**
 * Sauvegarde les mappings de pseudonymisation dans le stockage local
 */
function saveMappings() {
    try {
        localStorage.setItem('pseudonymizationMappings', JSON.stringify(pseudonymizationMappings));
    } catch (error) {
        console.error('Erreur lors de la sauvegarde des mappings de pseudonymisation:', error);
    }
}

/**
 * Anonymise une adresse email
 * @param {string} email - L'adresse email à anonymiser
 * @param {string} method - La méthode d'anonymisation à utiliser
 * @returns {string} - L'adresse email anonymisée
 */
function anonymizeEmail(email, method = anonymizationConfig.methods.PARTIAL) {
    if (!email) return '';
    
    switch (method) {
        case anonymizationConfig.methods.HASH:
            // Hachage complet (non réversible)
            return hashData(email);
            
        case anonymizationConfig.methods.PSEUDONYMIZE:
            // Pseudonymisation (potentiellement réversible)
            return pseudonymizeData(email, anonymizationConfig.dataTypes.EMAIL);
            
        case anonymizationConfig.methods.TOKENIZE:
            // Remplacement par un jeton
            return tokenizeData(email, anonymizationConfig.dataTypes.EMAIL);
            
        case anonymizationConfig.methods.PARTIAL:
        default:
            // Masquage partiel (ex: j***@example.com)
            const [username, domain] = email.split('@');
            
            let anonymizedUsername = '';
            if (username.length <= 2) {
                anonymizedUsername = '*'.repeat(username.length);
            } else {
                anonymizedUsername = username.charAt(0) + '*'.repeat(username.length - 2) + username.charAt(username.length - 1);
            }
            
            return anonymizedUsername + '@' + domain;
    }
}

/**
 * Anonymise une adresse IP
 * @param {string} ip - L'adresse IP à anonymiser
 * @param {string} method - La méthode d'anonymisation à utiliser
 * @returns {string} - L'adresse IP anonymisée
 */
function anonymizeIP(ip, method = anonymizationConfig.methods.PARTIAL) {
    if (!ip) return '';
    
    switch (method) {
        case anonymizationConfig.methods.HASH:
            // Hachage complet (non réversible)
            return hashData(ip);
            
        case anonymizationConfig.methods.PSEUDONYMIZE:
            // Pseudonymisation (potentiellement réversible)
            return pseudonymizeData(ip, anonymizationConfig.dataTypes.IP);
            
        case anonymizationConfig.methods.TOKENIZE:
            // Remplacement par un jeton
            return tokenizeData(ip, anonymizationConfig.dataTypes.IP);
            
        case anonymizationConfig.methods.PARTIAL:
        default:
            // Masquage partiel (ex: 192.168.xxx.xxx)
            const ipParts = ip.split('.');
            if (ipParts.length === 4) {
                // IPv4
                return `${ipParts[0]}.${ipParts[1]}.xxx.xxx`;
            } else {
                // IPv6 ou format non reconnu
                return hashData(ip).substring(0, 8) + '...';
            }
    }
}

/**
 * Anonymise un nom
 * @param {string} name - Le nom à anonymiser
 * @param {string} method - La méthode d'anonymisation à utiliser
 * @returns {string} - Le nom anonymisé
 */
function anonymizeName(name, method = anonymizationConfig.methods.PARTIAL) {
    if (!name) return '';
    
    switch (method) {
        case anonymizationConfig.methods.HASH:
            // Hachage complet (non réversible)
            return hashData(name);
            
        case anonymizationConfig.methods.PSEUDONYMIZE:
            // Pseudonymisation (potentiellement réversible)
            return pseudonymizeData(name, anonymizationConfig.dataTypes.NAME);
            
        case anonymizationConfig.methods.TOKENIZE:
            // Remplacement par un jeton
            return tokenizeData(name, anonymizationConfig.dataTypes.NAME);
            
        case anonymizationConfig.methods.PARTIAL:
        default:
            // Masquage partiel (ex: J*** D***)
            const nameParts = name.split(' ');
            return nameParts.map(part => {
                if (part.length <= 1) return part;
                return part.charAt(0) + '*'.repeat(part.length - 1);
            }).join(' ');
    }
}

/**
 * Hache une donnée de manière non réversible
 * @param {string} data - La donnée à hacher
 * @returns {string} - La donnée hachée
 */
function hashData(data) {
    // Dans un environnement de production, utiliser une fonction de hachage cryptographique
    // Pour cette démonstration, nous utilisons une fonction de hachage simple
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
        const char = data.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Conversion en entier 32 bits
    }
    
    // Convertir en chaîne hexadécimale
    return 'h' + Math.abs(hash).toString(16).padStart(8, '0');
}

/**
 * Pseudonymise une donnée (potentiellement réversible avec une clé)
 * @param {string} data - La donnée à pseudonymiser
 * @param {string} type - Le type de donnée
 * @returns {string} - La donnée pseudonymisée
 */
function pseudonymizeData(data, type) {
    // Vérifier si un mapping existe déjà pour cette donnée
    const mappingKey = `${type}:${hashData(data)}`;
    
    if (pseudonymizationMappings[mappingKey]) {
        return pseudonymizationMappings[mappingKey];
    }
    
    // Générer un nouveau pseudonyme
    const pseudonym = generatePseudonym(type);
    
    // Enregistrer le mapping
    pseudonymizationMappings[mappingKey] = pseudonym;
    saveMappings();
    
    return pseudonym;
}

/**
 * Génère un pseudonyme pour un type de donnée
 * @param {string} type - Le type de donnée
 * @returns {string} - Le pseudonyme généré
 */
function generatePseudonym(type) {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    
    switch (type) {
        case anonymizationConfig.dataTypes.EMAIL:
            return `user_${timestamp}${random}@anonymous.org`;
            
        case anonymizationConfig.dataTypes.IP:
            return `0.0.0.${Math.floor(Math.random() * 255)}`;
            
        case anonymizationConfig.dataTypes.NAME:
            return `User_${timestamp.substring(0, 4)}`;
            
        case anonymizationConfig.dataTypes.PHONE:
            return `+00000${Math.floor(Math.random() * 10000)}`;
            
        case anonymizationConfig.dataTypes.ADDRESS:
            return `Address_${random}`;
            
        case anonymizationConfig.dataTypes.ID:
            return `ID_${timestamp}${random}`;
            
        default:
            return `anon_${timestamp}${random}`;
    }
}

/**
 * Remplace une donnée par un jeton
 * @param {string} data - La donnée à tokeniser
 * @param {string} type - Le type de donnée
 * @returns {string} - Le jeton généré
 */
function tokenizeData(data, type) {
    // Générer un jeton unique
    const token = 'TKN_' + hashData(data + Date.now() + Math.random());
    
    // Dans un environnement de production, le mapping entre les jetons et les données originales
    // serait stocké de manière sécurisée, potentiellement dans un service distinct
    
    return token;
}

/**
 * Anonymise les données sensibles dans un objet
 * @param {Object} data - L'objet contenant les données à anonymiser
 * @param {Object} fieldMappings - Mappings des champs à anonymiser et leurs méthodes
 * @returns {Object} - L'objet avec les données anonymisées
 */
function anonymizeObject(data, fieldMappings) {
    if (!data || typeof data !== 'object') return data;
    
    const result = Array.isArray(data) ? [...data] : {...data};
    
    for (const [field, config] of Object.entries(fieldMappings)) {
        if (result[field] !== undefined && result[field] !== null) {
            const { type, method } = config;
            
            switch (type) {
                case anonymizationConfig.dataTypes.EMAIL:
                    result[field] = anonymizeEmail(result[field], method);
                    break;
                    
                case anonymizationConfig.dataTypes.IP:
                    result[field] = anonymizeIP(result[field], method);
                    break;
                    
                case anonymizationConfig.dataTypes.NAME:
                    result[field] = anonymizeName(result[field], method);
                    break;
                    
                // Ajouter d'autres types au besoin
                
                default:
                    // Type non reconnu, utiliser le hachage par défaut
                    result[field] = hashData(result[field]);
            }
        }
    }
    
    return result;
}

/**
 * Anonymise les données sensibles dans un tableau d'objets
 * @param {Array} dataArray - Le tableau d'objets à anonymiser
 * @param {Object} fieldMappings - Mappings des champs à anonymiser et leurs méthodes
 * @returns {Array} - Le tableau avec les données anonymisées
 */
function anonymizeDataArray(dataArray, fieldMappings) {
    if (!Array.isArray(dataArray)) return dataArray;
    
    return dataArray.map(item => anonymizeObject(item, fieldMappings));
}

/**
 * Vérifie si une donnée est déjà anonymisée
 * @param {string} data - La donnée à vérifier
 * @param {string} type - Le type de donnée
 * @returns {boolean} - Indique si la donnée est déjà anonymisée
 */
function isAlreadyAnonymized(data, type) {
    if (!data) return true;
    
    switch (type) {
        case anonymizationConfig.dataTypes.EMAIL:
            // Vérifier si l'email contient des astérisques ou commence par 'user_'
            return data.includes('*') || data.startsWith('user_') || data.startsWith('TKN_');
            
        case anonymizationConfig.dataTypes.IP:
            // Vérifier si l'IP contient 'xxx' ou commence par '0.0.0.'
            return data.includes('xxx') || data.startsWith('0.0.0.') || data.startsWith('TKN_');
            
        case anonymizationConfig.dataTypes.NAME:
            // Vérifier si le nom contient des astérisques ou commence par 'User_'
            return data.includes('*') || data.startsWith('User_') || data.startsWith('TKN_');
            
        default:
            // Pour les autres types, vérifier s'il s'agit d'un hachage ou d'un jeton
            return data.startsWith('h') && data.length === 9 || data.startsWith('TKN_');
    }
}

// Exposer les fonctions publiques
window.dataAnonymizer = {
    init: initAnonymizer,
    anonymizeEmail,
    anonymizeIP,
    anonymizeName,
    anonymizeObject,
    anonymizeDataArray,
    isAlreadyAnonymized,
    config: anonymizationConfig
};