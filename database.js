// Système de gestion de base de données sécurisée pour Tech Shield

// Simulation d'une base de données pour stocker les messages
// Dans un environnement de production, cela serait remplacé par une vraie base de données
const messagesDB = [];

// Configuration du chiffrement
const encryptionConfig = {
    algorithm: 'AES-256-GCM',  // Algorithme de chiffrement
    keyLength: 32,             // Longueur de la clé en octets (256 bits)
    ivLength: 12,              // Longueur du vecteur d'initialisation
    tagLength: 16              // Longueur du tag d'authentification
};

// Clé de chiffrement (dans un environnement de production, cette clé serait stockée de manière sécurisée)
// Cette clé est générée aléatoirement pour la démonstration
let encryptionKey = null;

// Configuration de la purge automatique
const purgeConfig = {
    maxAgeInDays: 30,           // Durée de conservation des messages en jours
    purgeInterval: 24 * 60 * 60 * 1000,  // Intervalle de purge en millisecondes (24h)
    enableLogging: true,       // Activer la journalisation des purges
    retainImportant: true      // Conserver les messages marqués comme importants
};

// Initialiser le système de base de données
function initDatabase() {
    // Générer une clé de chiffrement si elle n'existe pas déjà
    if (!encryptionKey) {
        generateEncryptionKey();
    }
    
    // Charger les messages depuis le localStorage
    loadMessagesFromStorage();
    
    // Démarrer le processus de purge automatique
    startAutoPurge();
    
    console.log('Système de base de données initialisé');
    return true;
}

// Fonction pour générer une clé de chiffrement
function generateEncryptionKey() {
    // Dans un environnement réel, cette clé serait stockée de manière sécurisée
    // Pour cette démonstration, nous générons une clé aléatoire
    const keyArray = new Uint8Array(encryptionConfig.keyLength);
    window.crypto.getRandomValues(keyArray);
    encryptionKey = keyArray;
    
    // Stocker la clé dans le sessionStorage (pour la démonstration uniquement)
    // Dans un environnement de production, la clé serait stockée de manière plus sécurisée
    const keyBase64 = arrayBufferToBase64(encryptionKey);
    sessionStorage.setItem('encryptionKey', keyBase64);
    
    return keyBase64;
}

// Fonction pour récupérer la clé de chiffrement
function getEncryptionKey() {
    if (encryptionKey) {
        return encryptionKey;
    }
    
    // Récupérer la clé depuis le sessionStorage
    const keyBase64 = sessionStorage.getItem('encryptionKey');
    if (keyBase64) {
        encryptionKey = base64ToArrayBuffer(keyBase64);
        return encryptionKey;
    }
    
    // Générer une nouvelle clé si aucune n'est trouvée
    return generateEncryptionKey();
}

// Fonction pour chiffrer un email
async function encryptEmail(email) {
    try {
        // Valider l'email
        if (!validateEmail(email)) {
            throw new Error('Format d\'email invalide');
        }
        
        // Convertir l'email en ArrayBuffer
        const encoder = new TextEncoder();
        const emailData = encoder.encode(email);
        
        // Générer un vecteur d'initialisation (IV) aléatoire
        const iv = window.crypto.getRandomValues(new Uint8Array(encryptionConfig.ivLength));
        
        // Récupérer la clé de chiffrement
        const key = await window.crypto.subtle.importKey(
            'raw',
            getEncryptionKey(),
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        
        // Chiffrer l'email
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: encryptionConfig.tagLength * 8 // en bits
            },
            key,
            emailData
        );
        
        // Combiner l'IV et les données chiffrées
        const result = new Uint8Array(iv.length + encryptedData.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encryptedData), iv.length);
        
        // Convertir le résultat en Base64 pour le stockage
        return arrayBufferToBase64(result);
    } catch (error) {
        console.error('Erreur lors du chiffrement de l\'email:', error);
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                'Erreur de chiffrement: ' + error.message
            );
        }
        throw error;
    }
}

// Fonction pour déchiffrer un email
async function decryptEmail(encryptedEmail) {
    try {
        // Convertir le Base64 en ArrayBuffer
        const encryptedData = base64ToArrayBuffer(encryptedEmail);
        
        // Extraire l'IV et les données chiffrées
        const iv = encryptedData.slice(0, encryptionConfig.ivLength);
        const ciphertext = encryptedData.slice(encryptionConfig.ivLength);
        
        // Récupérer la clé de chiffrement
        const key = await window.crypto.subtle.importKey(
            'raw',
            getEncryptionKey(),
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        // Déchiffrer l'email
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: encryptionConfig.tagLength * 8 // en bits
            },
            key,
            ciphertext
        );
        
        // Convertir le résultat en chaîne de caractères
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (error) {
        console.error('Erreur lors du déchiffrement de l\'email:', error);
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                'Erreur de déchiffrement: ' + error.message
            );
        }
        throw error;
    }
}

// Fonction pour ajouter un message
async function addMessage(email, message) {
    try {
        // Valider les entrées
        if (!validateEmail(email)) {
            throw new Error('Format d\'email invalide');
        }
        
        if (!validateMessage(message)) {
            throw new Error('Format de message invalide');
        }
        
        // Chiffrer l'email
        const encryptedEmail = await encryptEmail(email);
        
        // Créer l'objet message
        const newMessage = {
            id: generateMessageId(),
            email: encryptedEmail,
            message: sanitizeHTML(message),  // Assainir le message pour éviter les attaques XSS
            date: new Date().toISOString(),
            read: false,
            important: false  // Par défaut, les messages ne sont pas marqués comme importants
        };
        
        // Ajouter le message à la base de données
        messagesDB.push(newMessage);
        
        // Sauvegarder les messages dans le localStorage
        saveMessagesToStorage();
        
        // Enregistrer l'action dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.INFO,
                'Nouveau message ajouté'
            );
        }
        
        return { success: true, messageId: newMessage.id };
    } catch (error) {
        console.error('Erreur lors de l\'ajout du message:', error);
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                'Erreur d\'ajout de message: ' + error.message
            );
        }
        return { success: false, error: error.message };
    }
}

// Fonction pour récupérer tous les messages
async function getAllMessages(filters = {}) {
    try {
        // Vérifier si l'utilisateur est authentifié et a les droits d'administrateur
        if (!window.auth || !window.auth.isAuthenticated() || !window.auth.isAdmin()) {
            throw new Error('Accès non autorisé');
        }
        
        // Charger les messages depuis le localStorage
        loadMessagesFromStorage();
        
        // Filtrer les messages selon les critères fournis
        let filteredMessages = [...messagesDB];
        
        // Filtre par date de début
        if (filters.startDate) {
            const startDate = new Date(filters.startDate);
            filteredMessages = filteredMessages.filter(msg => new Date(msg.date) >= startDate);
        }
        
        // Filtre par date de fin
        if (filters.endDate) {
            const endDate = new Date(filters.endDate);
            filteredMessages = filteredMessages.filter(msg => new Date(msg.date) <= endDate);
        }
        
        // Filtre par statut de lecture
        if (filters.read !== undefined) {
            filteredMessages = filteredMessages.filter(msg => msg.read === filters.read);
        }
        
        // Filtre par importance
        if (filters.important !== undefined) {
            filteredMessages = filteredMessages.filter(msg => msg.important === filters.important);
        }
        
        // Filtre par contenu du message
        if (filters.searchText) {
            const searchText = filters.searchText.toLowerCase();
            filteredMessages = filteredMessages.filter(msg => {
                // Recherche dans le contenu du message
                return msg.message.toLowerCase().includes(searchText);
            });
        }
        
        // Créer une copie des messages avec les emails déchiffrés
        const messages = [];
        
        for (const message of filteredMessages) {
            try {
                const decryptedEmail = await decryptEmail(message.email);
                messages.push({
                    ...message,
                    email: decryptedEmail
                });
            } catch (decryptError) {
                // Si le déchiffrement échoue, utiliser une valeur par défaut
                messages.push({
                    ...message,
                    email: '[Email chiffré]'
                });
            }
        }
        
        return { success: true, messages, totalCount: messages.length };
    } catch (error) {
        console.error('Erreur lors de la récupération des messages:', error);
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                'Erreur de récupération des messages: ' + error.message
            );
        }
        return { success: false, error: error.message };
    }
}

// Fonction pour marquer un message comme lu
function markMessageAsRead(messageId) {
    try {
        // Vérifier si l'utilisateur est authentifié et a les droits d'administrateur
        if (!window.auth || !window.auth.isAuthenticated() || !window.auth.isAdmin()) {
            throw new Error('Accès non autorisé');
        }
        
        // Trouver le message
        const messageIndex = messagesDB.findIndex(msg => msg.id === messageId);
        
        if (messageIndex === -1) {
            throw new Error('Message non trouvé');
        }
        
        // Marquer le message comme lu
        messagesDB[messageIndex].read = true;
        
        // Sauvegarder les messages dans le localStorage
        saveMessagesToStorage();
        
        return { success: true };
    } catch (error) {
        console.error('Erreur lors du marquage du message comme lu:', error);
        return { success: false, error: error.message };
    }
}

// Fonction pour marquer un message comme important (ne sera pas supprimé lors de la purge automatique)
function markMessageAsImportant(messageId, isImportant = true) {
    try {
        // Vérifier si l'utilisateur est authentifié et a les droits d'administrateur
        if (!window.auth || !window.auth.isAuthenticated() || !window.auth.isAdmin()) {
            throw new Error('Accès non autorisé');
        }
        
        // Trouver le message
        const messageIndex = messagesDB.findIndex(msg => msg.id === messageId);
        
        if (messageIndex === -1) {
            throw new Error('Message non trouvé');
        }
        
        // Marquer le message comme important ou non
        messagesDB[messageIndex].important = isImportant;
        
        // Sauvegarder les messages dans le localStorage
        saveMessagesToStorage();
        
        // Enregistrer l'action dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.INFO,
                `Message ${isImportant ? 'marqué comme important' : 'non marqué comme important'}: ${messageId}`
            );
        }
        
        return { success: true };
    } catch (error) {
        console.error(`Erreur lors du marquage du message comme ${isImportant ? 'important' : 'non important'}:`, error);
        return { success: false, error: error.message };
    }
}

// Fonction pour supprimer un message
function deleteMessage(messageId) {
    try {
        // Vérifier si l'utilisateur est authentifié et a les droits d'administrateur
        if (!window.auth || !window.auth.isAuthenticated() || !window.auth.isAdmin()) {
            throw new Error('Accès non autorisé');
        }
        
        // Trouver le message
        const messageIndex = messagesDB.findIndex(msg => msg.id === messageId);
        
        if (messageIndex === -1) {
            throw new Error('Message non trouvé');
        }
        
        // Supprimer le message
        messagesDB.splice(messageIndex, 1);
        
        // Sauvegarder les messages dans le localStorage
        saveMessagesToStorage();
        
        // Enregistrer l'action dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.INFO,
                'Message supprimé: ' + messageId
            );
        }
        
        return { success: true };
    } catch (error) {
        console.error('Erreur lors de la suppression du message:', error);
        return { success: false, error: error.message };
    }
}

// Fonction pour purger les anciens messages
function purgeOldMessages() {
    try {
        const now = new Date();
        const cutoffDate = new Date(now.getTime() - (purgeConfig.maxAgeInDays * 24 * 60 * 60 * 1000));
        
        // Compter le nombre de messages avant la purge
        const initialCount = messagesDB.length;
        
        // Filtrer les messages plus récents que la date limite ou marqués comme importants
        const newMessages = messagesDB.filter(message => {
            const messageDate = new Date(message.date);
            
            // Conserver les messages récents
            if (messageDate >= cutoffDate) {
                return true;
            }
            
            // Conserver les messages importants si l'option est activée
            if (purgeConfig.retainImportant && message.important) {
                return true;
            }
            
            // Supprimer les autres messages
            return false;
        });
        
        // Mettre à jour la base de données
        messagesDB.length = 0;
        newMessages.forEach(message => messagesDB.push(message));
        
        // Sauvegarder les messages dans le localStorage
        saveMessagesToStorage();
        
        // Calculer le nombre de messages supprimés
        const deletedCount = initialCount - messagesDB.length;
        
        // Enregistrer l'action dans les logs de sécurité
        if (window.securityLogs && purgeConfig.enableLogging && deletedCount > 0) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.INFO,
                `Purge automatique: ${deletedCount} message(s) supprimé(s), ${messagesDB.length} message(s) conservé(s)`
            );
        }
        
        return { success: true, deletedCount, remainingCount: messagesDB.length };
    } catch (error) {
        console.error('Erreur lors de la purge des anciens messages:', error);
        
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs && purgeConfig.enableLogging) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                `Erreur lors de la purge automatique: ${error.message}`
            );
        }
        
        return { success: false, error: error.message };
    }
}

// Fonction pour démarrer la purge automatique
function startAutoPurge() {
    // Exécuter une purge immédiatement
    purgeOldMessages();
    
    // Planifier des purges régulières
    setInterval(purgeOldMessages, purgeConfig.purgeInterval);
}

// Fonction pour sauvegarder les messages dans le localStorage
function saveMessagesToStorage() {
    localStorage.setItem('messages', JSON.stringify(messagesDB));
}

// Fonction pour charger les messages depuis le localStorage
function loadMessagesFromStorage() {
    const storedMessages = localStorage.getItem('messages');
    if (storedMessages) {
        // Fusionner les messages stockés avec les messages actuels
        const parsedMessages = JSON.parse(storedMessages);
        
        // Vider le tableau actuel et ajouter les messages stockés
        messagesDB.length = 0;
        parsedMessages.forEach(message => messagesDB.push(message));
    }
}

// Fonction pour générer un ID unique pour les messages
function generateMessageId() {
    return 'msg-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
}

// Fonction pour valider un email
function validateEmail(email) {
    // Vérifier si l'email est null ou undefined
    if (!email) return false;
    
    // Vérifier la longueur de l'email
    if (email.length > 254) return false;
    
    // Utiliser une expression régulière pour valider le format de l'email
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

// Fonction pour valider un message
function validateMessage(message) {
    // Vérifier si le message est null ou undefined
    if (!message) return false;
    
    // Vérifier que le message n'est pas vide et qu'il ne dépasse pas une certaine longueur
    if (message.trim().length === 0 || message.length > 5000) return false;
    
    // Vérifier l'absence de caractères potentiellement dangereux pour les injections SQL
    const sqlInjectionPattern = /('(''|[^'])*')|(\/\*[\s\S]*?\*\/)|(--)|(#)|(\/\*.*\*\/)/i;
    if (sqlInjectionPattern.test(message)) return false;
    
    return true;
}

// Fonction pour assainir le HTML et prévenir les attaques XSS
function sanitizeHTML(html) {
    if (!html) return '';
    
    // Échapper les caractères spéciaux HTML
    const escaped = html
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    
    // Supprimer les balises script et les événements JavaScript
    const sanitized = escaped
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '');
    
    return sanitized;
}

// Fonction pour convertir un ArrayBuffer en Base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Fonction pour convertir un Base64 en ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// Fonction pour configurer la base de données
function configureDatabase(options = {}) {
    // Mettre à jour la configuration de purge si des options sont fournies
    if (options.purge) {
        if (typeof options.purge.maxAgeInDays === 'number') {
            purgeConfig.maxAgeInDays = options.purge.maxAgeInDays;
        }
        if (typeof options.purge.enableLogging === 'boolean') {
            purgeConfig.enableLogging = options.purge.enableLogging;
        }
        if (typeof options.purge.retainImportant === 'boolean') {
            purgeConfig.retainImportant = options.purge.retainImportant;
        }
    }
    
    // Mettre à jour la configuration de chiffrement si des options sont fournies
    if (options.encryption) {
        if (options.encryption.regenerateKey === true) {
            // Régénérer la clé de chiffrement
            generateEncryptionKey();
        }
    }
    
    return { success: true };
}

// Fonction pour rechercher des messages par texte
async function searchMessages(searchText) {
    try {
        // Vérifier si l'utilisateur est authentifié et a les droits d'administrateur
        if (!window.auth || !window.auth.isAuthenticated() || !window.auth.isAdmin()) {
            throw new Error('Accès non autorisé');
        }
        
        if (!searchText || typeof searchText !== 'string') {
            throw new Error('Texte de recherche invalide');
        }
        
        // Charger les messages depuis le localStorage
        loadMessagesFromStorage();
        
        // Convertir le texte de recherche en minuscules pour une recherche insensible à la casse
        const normalizedSearchText = searchText.toLowerCase();
        
        // Filtrer les messages qui contiennent le texte recherché
        const matchingMessages = [];
        
        for (const message of messagesDB) {
            // Vérifier si le message contient le texte recherché
            if (message.message.toLowerCase().includes(normalizedSearchText)) {
                try {
                    // Déchiffrer l'email pour l'affichage
                    const decryptedEmail = await decryptEmail(message.email);
                    matchingMessages.push({
                        ...message,
                        email: decryptedEmail
                    });
                } catch (decryptError) {
                    // Si le déchiffrement échoue, utiliser une valeur par défaut
                    matchingMessages.push({
                        ...message,
                        email: '[Email chiffré]'
                    });
                }
            }
        }
        
        return { 
            success: true, 
            messages: matchingMessages, 
            count: matchingMessages.length,
            searchText: searchText
        };
    } catch (error) {
        console.error('Erreur lors de la recherche de messages:', error);
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                'Erreur de recherche de messages: ' + error.message
            );
        }
        return { success: false, error: error.message };
    }
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.database = {
    initDatabase,
    configureDatabase,
    addMessage,
    getAllMessages,
    searchMessages,
    markMessageAsRead,
    markMessageAsImportant,
    deleteMessage,
    purgeOldMessages,
    validateEmail,
    validateMessage
};