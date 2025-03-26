/**
 * Module de gestion des événements pour Tech Shield
 * Ce module permet de gérer les événements (ajout, modification, suppression)
 * et les stocke dans le localStorage avec chiffrement
 */

window.events = (function() {
    // Clé de chiffrement pour sécuriser les données
    const ENCRYPTION_KEY = 'tech-shield-events-key';
    
    // Structure de données pour les événements
    let eventsList = [];
    
    /**
     * Chiffre une chaîne de caractères
     * @param {string} text - Texte à chiffrer
     * @returns {string} - Texte chiffré
     */
    function encrypt(text) {
        // Implémentation simple de chiffrement pour le stockage local
        // Dans un environnement de production, utilisez une bibliothèque de cryptographie robuste
        return btoa(ENCRYPTION_KEY + text);
    }
    
    /**
     * Déchiffre une chaîne de caractères
     * @param {string} encryptedText - Texte chiffré
     * @returns {string} - Texte déchiffré
     */
    function decrypt(encryptedText) {
        // Déchiffrement simple
        try {
            const decrypted = atob(encryptedText);
            if (decrypted.startsWith(ENCRYPTION_KEY)) {
                return decrypted.substring(ENCRYPTION_KEY.length);
            }
            return null;
        } catch (e) {
            console.error('Erreur de déchiffrement:', e);
            return null;
        }
    }
    
    /**
     * Sauvegarde les événements dans le localStorage
     */
    function saveEvents() {
        const encryptedData = encrypt(JSON.stringify(eventsList));
        localStorage.setItem('tech-shield-events', encryptedData);
    }
    
    /**
     * Charge les événements depuis le localStorage
     */
    function loadEvents() {
        const encryptedData = localStorage.getItem('tech-shield-events');
        if (encryptedData) {
            const decryptedData = decrypt(encryptedData);
            if (decryptedData) {
                try {
                    eventsList = JSON.parse(decryptedData);
                } catch (e) {
                    console.error('Erreur lors du chargement des événements:', e);
                    eventsList = [];
                }
            } else {
                eventsList = [];
            }
        } else {
            eventsList = [];
        }
    }
    
    /**
     * Génère un ID unique pour un événement
     * @returns {string} - ID unique
     */
    function generateEventId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
    }
    
    /**
     * Ajoute un nouvel événement
     * @param {Object} event - Événement à ajouter
     * @returns {Object} - Événement ajouté avec son ID
     */
    function addEvent(event) {
        if (!event.title || !event.start) {
            throw new Error('Le titre et la date de début sont obligatoires');
        }
        
        const newEvent = {
            id: generateEventId(),
            title: event.title,
            start: event.start,
            end: event.end || null,
            description: event.description || '',
            color: event.color || '#3788d8',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        eventsList.push(newEvent);
        saveEvents();
        
        // Journaliser l'action
        if (window.securityLogs) {
            window.securityLogs.addLog({
                action: 'Événement créé',
                details: `Événement "${newEvent.title}" créé`,
                status: window.securityLogs.LOG_TYPES.SUCCESS
            });
        }
        
        return newEvent;
    }
    
    /**
     * Met à jour un événement existant
     * @param {string} eventId - ID de l'événement à mettre à jour
     * @param {Object} updatedData - Nouvelles données de l'événement
     * @returns {Object|null} - Événement mis à jour ou null si non trouvé
     */
    function updateEvent(eventId, updatedData) {
        const eventIndex = eventsList.findIndex(event => event.id === eventId);
        
        if (eventIndex === -1) {
            return null;
        }
        
        const event = eventsList[eventIndex];
        const updatedEvent = {
            ...event,
            ...updatedData,
            updatedAt: new Date().toISOString()
        };
        
        eventsList[eventIndex] = updatedEvent;
        saveEvents();
        
        // Journaliser l'action
        if (window.securityLogs) {
            window.securityLogs.addLog({
                action: 'Événement modifié',
                details: `Événement "${updatedEvent.title}" modifié`,
                status: window.securityLogs.LOG_TYPES.SUCCESS
            });
        }
        
        return updatedEvent;
    }
    
    /**
     * Supprime un événement
     * @param {string} eventId - ID de l'événement à supprimer
     * @returns {boolean} - true si supprimé, false sinon
     */
    function deleteEvent(eventId) {
        const eventIndex = eventsList.findIndex(event => event.id === eventId);
        
        if (eventIndex === -1) {
            return false;
        }
        
        const deletedEvent = eventsList[eventIndex];
        eventsList.splice(eventIndex, 1);
        saveEvents();
        
        // Journaliser l'action
        if (window.securityLogs) {
            window.securityLogs.addLog({
                action: 'Événement supprimé',
                details: `Événement "${deletedEvent.title}" supprimé`,
                status: window.securityLogs.LOG_TYPES.WARNING
            });
        }
        
        return true;
    }
    
    /**
     * Récupère tous les événements
     * @returns {Array} - Liste des événements
     */
    function getAllEvents() {
        return [...eventsList];
    }
    
    /**
     * Récupère un événement par son ID
     * @param {string} eventId - ID de l'événement
     * @returns {Object|null} - Événement trouvé ou null
     */
    function getEventById(eventId) {
        return eventsList.find(event => event.id === eventId) || null;
    }
    
    /**
     * Initialise le module d'événements
     */
    function init() {
        loadEvents();
        console.log('Module de gestion des événements initialisé');
    }
    
    // Initialiser le module au chargement
    init();
    
    // API publique
    return {
        addEvent,
        updateEvent,
        deleteEvent,
        getAllEvents,
        getEventById
    };
})();