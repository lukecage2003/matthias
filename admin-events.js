/**
 * Module d'interface pour la gestion des événements dans l'administration
 * Ce module gère l'interface utilisateur du calendrier et les interactions avec le module events.js
 */

document.addEventListener("DOMContentLoaded", function() {
    // Vérifier si nous sommes sur la page d'administration
    if (!document.querySelector('.admin-container')) return;
    
    // Vérifier si le module events est disponible
    if (!window.events) {
        console.error('Le module de gestion des événements n\'est pas disponible');
        return;
    }
    
    // Référence aux éléments du DOM
    const eventsCalendarEl = document.getElementById('eventsCalendar');
    const eventForm = document.getElementById('eventForm');
    const updateEventForm = document.getElementById('updateEventForm');
    const editEventForm = document.getElementById('editEventForm');
    const addEventForm = document.getElementById('addEventForm');
    const deleteEventBtn = document.getElementById('deleteEventBtn');
    const cancelEditEventBtn = document.getElementById('cancelEditEventBtn');
    
    // Variables globales
    let calendar;
    let currentEventId = null;
    
    // Initialiser le calendrier si l'élément existe
    if (eventsCalendarEl) {
        initializeCalendar();
    }
    
    /**
     * Initialise le calendrier FullCalendar
     */
    function initializeCalendar() {
        calendar = new FullCalendar.Calendar(eventsCalendarEl, {
            initialView: 'dayGridMonth',
            headerToolbar: {
                left: 'prev,next today',
                center: 'title',
                right: 'dayGridMonth,timeGridWeek,timeGridDay'
            },
            locale: 'fr',
            editable: true,
            selectable: true,
            selectMirror: true,
            dayMaxEvents: true,
            events: loadEvents,
            select: handleDateSelect,
            eventClick: handleEventClick,
            eventDrop: handleEventDrop,
            eventResize: handleEventResize,
            height: 'auto'
        });
        
        calendar.render();
    }
    
    /**
     * Charge les événements depuis le module events.js
     * @param {Object} info - Informations sur la période demandée
     * @param {Function} successCallback - Fonction de rappel en cas de succès
     * @param {Function} failureCallback - Fonction de rappel en cas d'échec
     */
    function loadEvents(info, successCallback, failureCallback) {
        try {
            const events = window.events.getAllEvents();
            successCallback(events);
        } catch (error) {
            console.error('Erreur lors du chargement des événements:', error);
            failureCallback(error);
        }
    }
    
    /**
     * Gère la sélection d'une date dans le calendrier
     * @param {Object} selectInfo - Informations sur la sélection
     */
    function handleDateSelect(selectInfo) {
        // Réinitialiser le formulaire
        eventForm.reset();
        
        // Préremplir les dates
        document.getElementById('eventStart').value = formatDateTimeForInput(selectInfo.start);
        if (selectInfo.end) {
            document.getElementById('eventEnd').value = formatDateTimeForInput(selectInfo.end);
        }
        
        // Masquer le formulaire d'édition et afficher le formulaire d'ajout
        editEventForm.style.display = 'none';
        addEventForm.style.display = 'block';
        
        // Focus sur le champ titre
        document.getElementById('eventTitle').focus();
    }
    
    /**
     * Gère le clic sur un événement dans le calendrier
     * @param {Object} clickInfo - Informations sur l'événement cliqué
     */
    function handleEventClick(clickInfo) {
        // Récupérer l'ID de l'événement
        const eventId = clickInfo.event.id;
        currentEventId = eventId;
        
        // Récupérer les détails de l'événement
        const event = window.events.getEventById(eventId);
        if (!event) return;
        
        // Remplir le formulaire d'édition
        document.getElementById('editEventId').value = event.id;
        document.getElementById('editEventTitle').value = event.title;
        document.getElementById('editEventStart').value = formatDateTimeForInput(new Date(event.start));
        if (event.end) {
            document.getElementById('editEventEnd').value = formatDateTimeForInput(new Date(event.end));
        } else {
            document.getElementById('editEventEnd').value = '';
        }
        document.getElementById('editEventDescription').value = event.description || '';
        document.getElementById('editEventColor').value = event.color || '#3788d8';
        
        // Masquer le formulaire d'ajout et afficher le formulaire d'édition
        addEventForm.style.display = 'none';
        editEventForm.style.display = 'block';
        
        // Focus sur le champ titre
        document.getElementById('editEventTitle').focus();
    }
    
    /**
     * Gère le déplacement d'un événement dans le calendrier
     * @param {Object} dropInfo - Informations sur le déplacement
     */
    function handleEventDrop(dropInfo) {
        const eventId = dropInfo.event.id;
        const newStart = dropInfo.event.start;
        const newEnd = dropInfo.event.end;
        
        // Mettre à jour l'événement
        try {
            window.events.updateEvent(eventId, {
                start: newStart.toISOString(),
                end: newEnd ? newEnd.toISOString() : null
            });
        } catch (error) {
            console.error('Erreur lors de la mise à jour de l\'événement:', error);
            dropInfo.revert();
        }
    }
    
    /**
     * Gère le redimensionnement d'un événement dans le calendrier
     * @param {Object} resizeInfo - Informations sur le redimensionnement
     */
    function handleEventResize(resizeInfo) {
        const eventId = resizeInfo.event.id;
        const newEnd = resizeInfo.event.end;
        
        // Mettre à jour l'événement
        try {
            window.events.updateEvent(eventId, {
                end: newEnd.toISOString()
            });
        } catch (error) {
            console.error('Erreur lors de la mise à jour de l\'événement:', error);
            resizeInfo.revert();
        }
    }
    
    /**
     * Formate une date pour un champ input datetime-local
     * @param {Date} date - Date à formater
     * @returns {string} - Date formatée
     */
    function formatDateTimeForInput(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        
        return `${year}-${month}-${day}T${hours}:${minutes}`;
    }
    
    // Gestionnaire d'événement pour le formulaire d'ajout
    if (eventForm) {
        eventForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const title = document.getElementById('eventTitle').value;
            const start = document.getElementById('eventStart').value;
            const end = document.getElementById('eventEnd').value;
            const description = document.getElementById('eventDescription').value;
            const color = document.getElementById('eventColor').value;
            
            if (!title || !start) {
                alert('Le titre et la date de début sont obligatoires');
                return;
            }
            
            try {
                // Ajouter l'événement
                window.events.addEvent({
                    title,
                    start: new Date(start).toISOString(),
                    end: end ? new Date(end).toISOString() : null,
                    description,
                    color
                });
                
                // Réinitialiser le formulaire
                eventForm.reset();
                
                // Rafraîchir le calendrier
                calendar.refetchEvents();
                
                // Notification de succès
                alert('Événement ajouté avec succès');
            } catch (error) {
                console.error('Erreur lors de l\'ajout de l\'événement:', error);
                alert('Erreur lors de l\'ajout de l\'événement: ' + error.message);
            }
        });
    }
    
    // Gestionnaire d'événement pour le formulaire de mise à jour
    if (updateEventForm) {
        updateEventForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const eventId = document.getElementById('editEventId').value;
            const title = document.getElementById('editEventTitle').value;
            const start = document.getElementById('editEventStart').value;
            const end = document.getElementById('editEventEnd').value;
            const description = document.getElementById('editEventDescription').value;
            const color = document.getElementById('editEventColor').value;
            
            if (!eventId || !title || !start) {
                alert('Le titre et la date de début sont obligatoires');
                return;
            }
            
            try {
                // Mettre à jour l'événement
                window.events.updateEvent(eventId, {
                    title,
                    start: new Date(start).toISOString(),
                    end: end ? new Date(end).toISOString() : null,
                    description,
                    color
                });
                
                // Masquer le formulaire d'édition
                editEventForm.style.display = 'none';
                addEventForm.style.display = 'block';
                
                // Réinitialiser le formulaire d'ajout
                eventForm.reset();
                
                // Rafraîchir le calendrier
                calendar.refetchEvents();
                
                // Réinitialiser l'ID de l'événement courant
                currentEventId = null;
                
                // Notification de succès
                alert('Événement mis à jour avec succès');
            } catch (error) {
                console.error('Erreur lors de la mise à jour de l\'événement:', error);
                alert('Erreur lors de la mise à jour de l\'événement: ' + error.message);
            }
        });
    }
    
    // Gestionnaire d'événement pour le bouton de suppression
    if (deleteEventBtn) {
        deleteEventBtn.addEventListener('click', function() {
            if (!currentEventId) return;
            
            if (confirm('Êtes-vous sûr de vouloir supprimer cet événement ?')) {
                try {
                    // Supprimer l'événement
                    window.events.deleteEvent(currentEventId);
                    
                    // Masquer le formulaire d'édition
                    editEventForm.style.display = 'none';
                    addEventForm.style.display = 'block';
                    
                    // Réinitialiser le formulaire d'ajout
                    eventForm.reset();
                    
                    // Rafraîchir le calendrier
                    calendar.refetchEvents();
                    
                    // Réinitialiser l'ID de l'événement courant
                    currentEventId = null;
                    
                    // Notification de succès
                    alert('Événement supprimé avec succès');
                } catch (error) {
                    console.error('Erreur lors de la suppression de l\'événement:', error);
                    alert('Erreur lors de la suppression de l\'événement: ' + error.message);
                }
            }
        });
    }
    
    // Gestionnaire d'événement pour le bouton d'annulation
    if (cancelEditEventBtn) {
        cancelEditEventBtn.addEventListener('click', function() {
            // Masquer le formulaire d'édition
            editEventForm.style.display = 'none';
            addEventForm.style.display = 'block';
            
            // Réinitialiser le formulaire d'ajout
            eventForm.reset();
            
            // Réinitialiser l'ID de l'événement courant
            currentEventId = null;
        });
    }
    
    // Gestionnaire d'événement pour l'onglet Événements
    const eventsTabLink = document.querySelector('.admin-nav a[data-tab="events"]');
    if (eventsTabLink) {
        eventsTabLink.addEventListener('click', function() {
            // Redimensionner le calendrier après l'affichage de l'onglet
            setTimeout(() => {
                if (calendar) {
                    calendar.updateSize();
                }
            }, 100);
        });
    }
});