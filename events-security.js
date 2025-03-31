/**
 * Module de sécurité pour les événements de Tech Shield
 * Ce module améliore la sécurité du module events.js en implémentant des fonctions
 * d'échappement HTML et de validation des entrées pour prévenir les attaques XSS
 */

(function() {
    // Vérifier si le module events est disponible
    if (!window.events) {
        console.error('Le module de gestion des événements n\'est pas disponible');
        return;
    }
    
    // Sauvegarder les fonctions originales
    const originalAddEvent = window.events.addEvent;
    const originalUpdateEvent = window.events.updateEvent;
    const originalGetAllEvents = window.events.getAllEvents;
    const originalGetEventById = window.events.getEventById;
    
    /**
     * Fonction robuste d'échappement HTML pour prévenir les attaques XSS
     * @param {string} text - Texte à échapper
     * @returns {string} - Texte échappé
     */
    function escapeHtml(text) {
        if (text === undefined || text === null) return '';
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;")
            .replace(/`/g, "&#96;")
            .replace(/\//g, "&#47;");
    }
    
    /**
     * Valide et assainit les données d'un événement
     * @param {Object} event - Événement à valider
     * @returns {Object} - Événement validé et assaini
     */
    function sanitizeEventData(event) {
        if (!event) return event;
        
        // Créer une copie de l'événement pour ne pas modifier l'original
        const sanitizedEvent = { ...event };
        
        // Échapper les champs textuels pour prévenir les attaques XSS
        if (sanitizedEvent.title) {
            sanitizedEvent.title = escapeHtml(sanitizedEvent.title);
        }
        
        if (sanitizedEvent.description) {
            sanitizedEvent.description = escapeHtml(sanitizedEvent.description);
        }
        
        // Valider les dates
        if (sanitizedEvent.start && !(sanitizedEvent.start instanceof Date) && isNaN(Date.parse(sanitizedEvent.start))) {
            throw new Error('Date de début invalide');
        }
        
        if (sanitizedEvent.end && !(sanitizedEvent.end instanceof Date) && isNaN(Date.parse(sanitizedEvent.end))) {
            throw new Error('Date de fin invalide');
        }
        
        // Valider la couleur (format hexadécimal)
        if (sanitizedEvent.color && !/^#[0-9A-F]{6}$/i.test(sanitizedEvent.color)) {
            // Si la couleur n'est pas au format hexadécimal, utiliser une couleur par défaut
            sanitizedEvent.color = '#3788d8';
        }
        
        return sanitizedEvent;
    }
    
    /**
     * Assainit un tableau d'événements
     * @param {Array} events - Tableau d'événements à assainir
     * @returns {Array} - Tableau d'événements assainis
     */
    function sanitizeEvents(events) {
        if (!Array.isArray(events)) return [];
        return events.map(event => {
            // Créer une copie de l'événement pour ne pas modifier l'original
            const sanitizedEvent = { ...event };
            
            // Échapper les champs textuels pour prévenir les attaques XSS
            if (sanitizedEvent.title) {
                sanitizedEvent.title = escapeHtml(sanitizedEvent.title);
            }
            
            if (sanitizedEvent.description) {
                sanitizedEvent.description = escapeHtml(sanitizedEvent.description);
            }
            
            return sanitizedEvent;
        });
    }
    
    // Remplacer la fonction addEvent par une version sécurisée
    window.events.addEvent = function(event) {
        // Valider et assainir les données de l'événement
        const sanitizedEvent = sanitizeEventData(event);
        
        // Appeler la fonction originale avec les données assainies
        return originalAddEvent.call(window.events, sanitizedEvent);
    };
    
    // Remplacer la fonction updateEvent par une version sécurisée
    window.events.updateEvent = function(eventId, updatedData) {
        // Valider et assainir les données de l'événement
        const sanitizedData = sanitizeEventData(updatedData);
        
        // Appeler la fonction originale avec les données assainies
        return originalUpdateEvent.call(window.events, eventId, sanitizedData);
    };
    
    // Remplacer la fonction getAllEvents par une version sécurisée
    window.events.getAllEvents = function() {
        // Récupérer tous les événements
        const events = originalGetAllEvents.call(window.events);
        
        // Assainir les événements avant de les retourner
        return sanitizeEvents(events);
    };
    
    // Remplacer la fonction getEventById par une version sécurisée
    window.events.getEventById = function(eventId) {
        // Récupérer l'événement
        const event = originalGetEventById.call(window.events, eventId);
        
        // Assainir l'événement avant de le retourner
        if (event) {
            // Créer une copie de l'événement pour ne pas modifier l'original
            const sanitizedEvent = { ...event };
            
            // Échapper les champs textuels pour prévenir les attaques XSS
            if (sanitizedEvent.title) {
                sanitizedEvent.title = escapeHtml(sanitizedEvent.title);
            }
            
            if (sanitizedEvent.description) {
                sanitizedEvent.description = escapeHtml(sanitizedEvent.description);
            }
            
            return sanitizedEvent;
        }
        
        return event;
    };
    
    console.log('Module de sécurité pour les événements initialisé');
})();