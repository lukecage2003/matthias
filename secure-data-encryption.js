// Module de chiffrement sécurisé pour Tech Shield
// Implémentation du chiffrement AES-256 pour les données sensibles

// Configuration du chiffrement
const secureEncryptionConfig = {
    algorithm: 'AES-256-GCM',  // Algorithme de chiffrement
    keyLength: 32,             // Longueur de la clé en octets (256 bits)
    ivLength: 12,              // Longueur du vecteur d'initialisation
    tagLength: 16,             // Longueur du tag d'authentification
    saltLength: 16,            // Longueur du sel pour dérivation de clé
    iterations: 100000,        // Nombre d'itérations pour PBKDF2
    keyStorage: 'secure'       // Mode de stockage de la clé ('secure', 'session', 'local')
};

// Clé maître (dans un environnement de production, cette clé serait stockée dans un HSM ou un coffre-fort comme HashiCorp Vault)
let masterKey = null;

/**
 * Initialise le système de chiffrement
 * @param {Object} config - Configuration optionnelle pour remplacer les valeurs par défaut
 * @returns {Promise<boolean>} - Succès de l'initialisation
 */
async function initSecureEncryption(config = {}) {
    try {
        // Fusionner la configuration fournie avec la configuration par défaut
        Object.assign(secureEncryptionConfig, config);
        
        // Générer ou récupérer la clé maître
        await getOrGenerateMasterKey();
        
        console.log('Système de chiffrement sécurisé initialisé');
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'initialisation du système de chiffrement:', error);
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.CRITICAL,
                details: 'Échec de l\'initialisation du système de chiffrement: ' + error.message,
                source: 'secure-encryption'
            });
        }
        return false;
    }
}

/**
 * Génère ou récupère la clé maître
 * @returns {Promise<CryptoKey>} - La clé maître
 */
async function getOrGenerateMasterKey() {
    // Si la clé existe déjà en mémoire, la retourner
    if (masterKey) {
        return masterKey;
    }
    
    // Essayer de récupérer la clé depuis le stockage
    const storedKey = await retrieveKeyFromStorage();
    if (storedKey) {
        masterKey = storedKey;
        return masterKey;
    }
    
    // Générer une nouvelle clé
    masterKey = await generateMasterKey();
    
    // Stocker la clé selon la configuration
    await storeKeyInStorage(masterKey);
    
    return masterKey;
}

/**
 * Génère une nouvelle clé maître
 * @returns {Promise<CryptoKey>} - La clé générée
 */
async function generateMasterKey() {
    try {
        // Générer une clé aléatoire pour AES-256-GCM
        const key = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: secureEncryptionConfig.keyLength * 8 // en bits
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
        
        // Journaliser la génération de clé si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: 'Nouvelle clé maître générée',
                source: 'secure-encryption'
            });
        }
        
        return key;
    } catch (error) {
        console.error('Erreur lors de la génération de la clé maître:', error);
        throw error;
    }
}

/**
 * Stocke la clé maître selon la configuration
 * @param {CryptoKey} key - La clé à stocker
 * @returns {Promise<boolean>} - Succès du stockage
 */
async function storeKeyInStorage(key) {
    try {
        // Exporter la clé en format brut
        const rawKey = await window.crypto.subtle.exportKey('raw', key);
        
        // Convertir en Base64 pour le stockage
        const keyBase64 = arrayBufferToBase64(rawKey);
        
        // Stocker selon la configuration
        switch (secureEncryptionConfig.keyStorage) {
            case 'session':
                sessionStorage.setItem('masterEncryptionKey', keyBase64);
                break;
            case 'local':
                localStorage.setItem('masterEncryptionKey', keyBase64);
                break;
            case 'secure':
                // Dans un environnement réel, la clé serait stockée dans un HSM ou un coffre-fort
                // Pour cette démonstration, nous utilisons sessionStorage
                sessionStorage.setItem('masterEncryptionKey', keyBase64);
                break;
            default:
                throw new Error('Mode de stockage de clé non pris en charge');
        }
        
        return true;
    } catch (error) {
        console.error('Erreur lors du stockage de la clé maître:', error);
        throw error;
    }
}

/**
 * Récupère la clé maître depuis le stockage
 * @returns {Promise<CryptoKey|null>} - La clé récupérée ou null si non trouvée
 */
async function retrieveKeyFromStorage() {
    try {
        let keyBase64 = null;
        
        // Récupérer selon la configuration
        switch (secureEncryptionConfig.keyStorage) {
            case 'session':
                keyBase64 = sessionStorage.getItem('masterEncryptionKey');
                break;
            case 'local':
                keyBase64 = localStorage.getItem('masterEncryptionKey');
                break;
            case 'secure':
                // Dans un environnement réel, la clé serait récupérée depuis un HSM ou un coffre-fort
                // Pour cette démonstration, nous utilisons sessionStorage
                keyBase64 = sessionStorage.getItem('masterEncryptionKey');
                break;
            default:
                throw new Error('Mode de stockage de clé non pris en charge');
        }
        
        if (!keyBase64) {
            return null;
        }
        
        // Convertir de Base64 en ArrayBuffer
        const rawKey = base64ToArrayBuffer(keyBase64);
        
        // Importer la clé
        return await window.crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM' },
            false, // non extractable pour la sécurité
            ['encrypt', 'decrypt']
        );
    } catch (error) {
        console.error('Erreur lors de la récupération de la clé maître:', error);
        return null;
    }
}

/**
 * Chiffre des données sensibles avec AES-256-GCM
 * @param {string} data - Les données à chiffrer
 * @param {string} context - Contexte des données (ex: 'email', 'password')
 * @returns {Promise<string>} - Les données chiffrées en Base64
 */
async function encryptData(data, context = 'generic') {
    try {
        // Valider les données
        if (!data) {
            throw new Error('Données vides');
        }
        
        // Obtenir la clé maître
        const key = await getOrGenerateMasterKey();
        
        // Générer un vecteur d'initialisation (IV) aléatoire
        const iv = window.crypto.getRandomValues(new Uint8Array(secureEncryptionConfig.ivLength));
        
        // Convertir les données en ArrayBuffer
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        
        // Ajouter des métadonnées pour l'authentification
        const metadata = encoder.encode(JSON.stringify({
            context: context,
            timestamp: new Date().toISOString(),
            version: '1.0'
        }));
        
        // Chiffrer les données
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: metadata, // Données authentifiées supplémentaires
                tagLength: secureEncryptionConfig.tagLength * 8 // en bits
            },
            key,
            dataBuffer
        );
        
        // Combiner l'IV, les métadonnées et les données chiffrées
        const result = new Uint8Array(iv.length + metadata.length + 4 + encryptedData.byteLength);
        result.set(iv, 0); // IV au début
        
        // Ajouter la taille des métadonnées (4 octets)
        const metadataLength = new Uint32Array([metadata.length]);
        result.set(new Uint8Array(metadataLength.buffer), iv.length);
        
        // Ajouter les métadonnées
        result.set(metadata, iv.length + 4);
        
        // Ajouter les données chiffrées
        result.set(new Uint8Array(encryptedData), iv.length + 4 + metadata.length);
        
        // Convertir le résultat en Base64 pour le stockage
        return arrayBufferToBase64(result);
    } catch (error) {
        console.error('Erreur lors du chiffrement des données:', error);
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: 'Erreur de chiffrement: ' + error.message,
                source: 'secure-encryption',
                context: context
            });
        }
        throw error;
    }
}

/**
 * Déchiffre des données sensibles avec AES-256-GCM
 * @param {string} encryptedData - Les données chiffrées en Base64
 * @returns {Promise<Object>} - Les données déchiffrées et leur contexte
 */
async function decryptData(encryptedData) {
    try {
        // Convertir le Base64 en ArrayBuffer
        const data = base64ToArrayBuffer(encryptedData);
        
        // Extraire l'IV
        const iv = data.slice(0, secureEncryptionConfig.ivLength);
        
        // Extraire la taille des métadonnées
        const metadataLengthBuffer = data.slice(secureEncryptionConfig.ivLength, secureEncryptionConfig.ivLength + 4);
        const metadataLength = new Uint32Array(metadataLengthBuffer)[0];
        
        // Extraire les métadonnées
        const metadataBuffer = data.slice(secureEncryptionConfig.ivLength + 4, secureEncryptionConfig.ivLength + 4 + metadataLength);
        const decoder = new TextDecoder();
        const metadata = JSON.parse(decoder.decode(metadataBuffer));
        
        // Extraire les données chiffrées
        const ciphertext = data.slice(secureEncryptionConfig.ivLength + 4 + metadataLength);
        
        // Obtenir la clé maître
        const key = await getOrGenerateMasterKey();
        
        // Déchiffrer les données
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: metadataBuffer, // Données authentifiées supplémentaires
                tagLength: secureEncryptionConfig.tagLength * 8 // en bits
            },
            key,
            ciphertext
        );
        
        // Convertir le résultat en chaîne de caractères
        const decryptedText = decoder.decode(decryptedBuffer);
        
        // Retourner les données déchiffrées et leur contexte
        return {
            data: decryptedText,
            context: metadata.context,
            timestamp: metadata.timestamp,
            version: metadata.version
        };
    } catch (error) {
        console.error('Erreur lors du déchiffrement des données:', error);
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: 'Erreur de déchiffrement: ' + error.message,
                source: 'secure-encryption'
            });
        }
        throw error;
    }
}

/**
 * Chiffre spécifiquement un email avec AES-256-GCM
 * @param {string} email - L'email à chiffrer
 * @returns {Promise<string>} - L'email chiffré en Base64
 */
async function encryptEmail(email) {
    // Valider l'email
    if (!validateEmail(email)) {
        throw new Error('Format d\'email invalide');
    }
    
    return await encryptData(email, 'email');
}

/**
 * Déchiffre un email
 * @param {string} encryptedEmail - L'email chiffré en Base64
 * @returns {Promise<string>} - L'email déchiffré
 */
async function decryptEmail(encryptedEmail) {
    const result = await decryptData(encryptedEmail);
    
    // Vérifier que le contexte est bien 'email'
    if (result.context !== 'email') {
        throw new Error('Les données déchiffrées ne sont pas un email');
    }
    
    return result.data;
}

/**
 * Valide un format d'email
 * @param {string} email - L'email à valider
 * @returns {boolean} - True si l'email est valide
 */
function validateEmail(email) {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

/**
 * Convertit un ArrayBuffer en chaîne Base64
 * @param {ArrayBuffer} buffer - Le buffer à convertir
 * @returns {string} - La chaîne Base64
 */
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convertit une chaîne Base64 en ArrayBuffer
 * @param {string} base64 - La chaîne Base64
 * @returns {ArrayBuffer} - Le buffer
 */
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Exposer les fonctions publiques
window.secureEncryption = {
    init: initSecureEncryption,
    encrypt: encryptData,
    decrypt: decryptData,
    encryptEmail: encryptEmail,
    decryptEmail: decryptEmail
};