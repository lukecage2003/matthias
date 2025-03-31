// Script de mise à jour de FullCalendar
// Ce script remplace les anciennes références à FullCalendar 5.10.1 par la version 6.1.10

document.addEventListener('DOMContentLoaded', function() {
    console.log('Vérification des mises à jour de FullCalendar...');
    
    // Vérifier si FullCalendar est utilisé dans la page
    const oldFullCalendarCSS = document.querySelector('link[href*="fullcalendar@5"]');
    const oldFullCalendarJS = document.querySelector('script[src*="fullcalendar@5"]');
    const oldFullCalendarLocale = document.querySelector('script[src*="fullcalendar@5"][src*="locales"]');
    
    if (oldFullCalendarCSS || oldFullCalendarJS) {
        console.log('Ancienne version de FullCalendar détectée. Mise à jour vers la version 6.1.10...');
        
        // Mettre à jour le CSS
        if (oldFullCalendarCSS) {
            const newCSSLink = document.createElement('link');
            newCSSLink.rel = 'stylesheet';
            newCSSLink.href = 'https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/main.min.css';
            document.head.appendChild(newCSSLink);
            
            // Supprimer l'ancien lien après chargement du nouveau
            newCSSLink.onload = function() {
                oldFullCalendarCSS.remove();
                console.log('CSS de FullCalendar mis à jour avec succès');
            };
        }
        
        // Mettre à jour le JS principal
        if (oldFullCalendarJS) {
            const newJSScript = document.createElement('script');
            newJSScript.src = 'https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/main.min.js';
            document.head.appendChild(newJSScript);
            
            // Supprimer l'ancien script après chargement du nouveau
            newJSScript.onload = function() {
                // Ne pas supprimer immédiatement pour éviter les erreurs
                setTimeout(() => {
                    oldFullCalendarJS.remove();
                    console.log('JS de FullCalendar mis à jour avec succès');
                    
                    // Réinitialiser le calendrier si nécessaire
                    if (window.calendar && typeof window.calendar.render === 'function') {
                        try {
                            window.calendar.render();
                            console.log('Calendrier réinitialisé avec succès');
                        } catch (error) {
                            console.error('Erreur lors de la réinitialisation du calendrier:', error);
                        }
                    }
                }, 1000);
            };
        }
        
        // Mettre à jour le fichier de localisation
        if (oldFullCalendarLocale) {
            const newLocaleScript = document.createElement('script');
            newLocaleScript.src = 'https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/locales/fr.js';
            document.head.appendChild(newLocaleScript);
            
            // Supprimer l'ancien script après chargement du nouveau
            newLocaleScript.onload = function() {
                setTimeout(() => {
                    oldFullCalendarLocale.remove();
                    console.log('Localisation de FullCalendar mise à jour avec succès');
                }, 1000);
            };
        }
        
        // Journaliser la mise à jour si le module de logs est disponible
        if (window.securityLogs && window.securityLogs.addLog) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: 'Mise à jour de FullCalendar de la version 5.10.1 vers 6.1.10',
                source: 'fullcalendar-update'
            });
        }
    } else {
        console.log('Aucune ancienne version de FullCalendar détectée ou déjà à jour.');
    }
});