// Module de gestion RGPD pour Tech Shield

document.addEventListener('DOMContentLoaded', function() {
    // Initialiser les composants RGPD
    initRGPDComponents();
    
    // Ajouter les gestionnaires d'événements
    setupEventListeners();
});

/**
 * Initialise les composants RGPD
 */
function initRGPDComponents() {
    // Vérifier si le module de chiffrement est disponible
    if (window.secureEncryption) {
        console.log('Module de chiffrement détecté, initialisation des composants RGPD');
    } else {
        console.warn('Module de chiffrement non détecté, certaines fonctionnalités RGPD peuvent être limitées');
    }
    
    // Vérifier si le module de logs est disponible
    if (window.securityLogs) {
        console.log('Module de logs détecté, journalisation RGPD activée');
    }
}

/**
 * Configure les écouteurs d'événements
 */
function setupEventListeners() {
    const deletionForm = document.getElementById('data-deletion-form');
    if (deletionForm) {
        deletionForm.addEventListener('submit', handleDeletionRequest);
    }
}

/**
 * Gère la soumission du formulaire de demande de suppression
 * @param {Event} event - L'événement de soumission
 */
function handleDeletionRequest(event) {
    event.preventDefault();
    
    // Récupérer les données du formulaire
    const email = document.getElementById('email').value;
    const deletionType = document.getElementById('deletion-type').value;
    const reason = document.getElementById('reason').value;
    const verificationCode = document.getElementById('verification-code').value;
    const consent = document.getElementById('consent').checked;
    
    // Valider les données
    if (!validateDeletionForm(email, deletionType, verificationCode, consent)) {
        return;
    }
    
    // Simuler l'envoi d'un code de vérification
    if (verificationCode !== '123456') { // Code de démonstration
        showFormResponse('error', 'Code de vérification invalide. Veuillez vérifier votre email et réessayer.');
        return;
    }
    
    // Créer la demande de suppression
    const deletionRequest = {
        email: anonymizeEmail(email),
        type: deletionType,
        reason: reason,
        requestDate: new Date().toISOString(),
        status: 'pending',
        requestId: generateRequestId()
    };
    
    // Enregistrer la demande
    saveDeletionRequest(deletionRequest);
    
    // Journaliser la demande si le module de logs est disponible
    if (window.securityLogs) {
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: `Demande de suppression RGPD reçue: ${deletionRequest.requestId}`,
            source: 'rgpd-module'
        });
    }
    
    // Afficher un message de confirmation
    showFormResponse('success', 'Votre demande de suppression a été enregistrée. Nous la traiterons dans un délai de 30 jours. Un email de confirmation vous a été envoyé.');
    
    // Réinitialiser le formulaire
    document.getElementById('data-deletion-form').reset();
}

/**
 * Valide les données du formulaire de suppression
 * @param {string} email - L'adresse email
 * @param {string} deletionType - Le type de suppression
 * @param {string} verificationCode - Le code de vérification
 * @param {boolean} consent - Le consentement
 * @returns {boolean} - Indique si les données sont valides
 */
function validateDeletionForm(email, deletionType, verificationCode, consent) {
    // Vérifier l'email
    if (!email || !validateEmail(email)) {
        showFormResponse('error', 'Veuillez fournir une adresse email valide.');
        return false;
    }
    
    // Vérifier le type de suppression
    if (!deletionType) {
        showFormResponse('error', 'Veuillez sélectionner un type de suppression.');
        return false;
    }
    
    // Vérifier le code de vérification
    if (!verificationCode) {
        showFormResponse('error', 'Veuillez entrer le code de vérification.');
        return false;
    }
    
    // Vérifier le consentement
    if (!consent) {
        showFormResponse('error', 'Vous devez confirmer être le propriétaire des données.');
        return false;
    }
    
    return true;
}

/**
 * Valide le format d'une adresse email
 * @param {string} email - L'adresse email à valider
 * @returns {boolean} - Indique si l'email est valide
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Affiche un message de réponse dans le formulaire
 * @param {string} type - Le type de message ('success' ou 'error')
 * @param {string} message - Le message à afficher
 */
function showFormResponse(type, message) {
    const responseElement = document.getElementById('form-response');
    if (responseElement) {
        responseElement.className = type === 'success' ? 'alert alert-success' : 'alert alert-danger';
        responseElement.textContent = message;
        responseElement.style.display = 'block';
        
        // Faire défiler jusqu'au message
        responseElement.scrollIntoView({ behavior: 'smooth' });
    }
}

/**
 * Génère un identifiant unique pour une demande
 * @returns {string} - L'identifiant généré
 */
function generateRequestId() {
    return 'REQ-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
}

/**
 * Enregistre une demande de suppression
 * @param {Object} request - La demande à enregistrer
 */
function saveDeletionRequest(request) {
    // Récupérer les demandes existantes
    let deletionRequests = [];
    const storedRequests = localStorage.getItem('deletionRequests');
    
    if (storedRequests) {
        try {
            deletionRequests = JSON.parse(storedRequests);
        } catch (error) {
            console.error('Erreur lors de la récupération des demandes:', error);
        }
    }
    
    // Ajouter la nouvelle demande
    deletionRequests.push(request);
    
    // Enregistrer les demandes
    localStorage.setItem('deletionRequests', JSON.stringify(deletionRequests));
}

/**
 * Anonymise une adresse email pour le stockage
 * @param {string} email - L'adresse email à anonymiser
 * @returns {string} - L'adresse email anonymisée
 */
function anonymizeEmail(email) {
    if (!email) return '';
    
    // Séparer le nom d'utilisateur et le domaine
    const [username, domain] = email.split('@');
    
    // Anonymiser le nom d'utilisateur
    let anonymizedUsername = '';
    if (username.length <= 2) {
        anonymizedUsername = '*'.repeat(username.length);
    } else {
        anonymizedUsername = username.charAt(0) + '*'.repeat(username.length - 2) + username.charAt(username.length - 1);
    }
    
    return anonymizedUsername + '@' + domain;
}

/**
 * Traite une demande de suppression (à implémenter côté serveur dans un environnement de production)
 * @param {string} requestId - L'identifiant de la demande
 * @param {string} email - L'adresse email associée à la demande
 * @param {string} deletionType - Le type de suppression
 */
function processDeletionRequest(requestId, email, deletionType) {
    // Cette fonction simule le traitement d'une demande de suppression
    // Dans un environnement de production, cette logique serait implémentée côté serveur
    
    console.log(`Traitement de la demande ${requestId} pour ${email}`);
    
    switch (deletionType) {
        case 'account':
            // Supprimer le compte complet
            if (window.auth && window.auth.removeUser) {
                window.auth.removeUser(email);
            }
            break;
            
        case 'cv':
            // Supprimer les données de CV
            // Implémentation à faire
            break;
            
        case 'messages':
            // Supprimer les messages
            if (window.database && window.database.deleteMessagesByEmail) {
                window.database.deleteMessagesByEmail(email);
            }
            break;
            
        case 'logs':
            // Anonymiser les logs
            if (window.securityLogs && window.securityLogs.anonymizeLogsByEmail) {
                window.securityLogs.anonymizeLogsByEmail(email);
            }
            break;
    }
    
    // Mettre à jour le statut de la demande
    updateRequestStatus(requestId, 'completed');
    
    // Journaliser le traitement
    if (window.securityLogs) {
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: `Demande de suppression RGPD traitée: ${requestId}`,
            source: 'rgpd-module'
        });
    }
}

/**
 * Met à jour le statut d'une demande
 * @param {string} requestId - L'identifiant de la demande
 * @param {string} status - Le nouveau statut
 */
function updateRequestStatus(requestId, status) {
    // Récupérer les demandes existantes
    let deletionRequests = [];
    const storedRequests = localStorage.getItem('deletionRequests');
    
    if (storedRequests) {
        try {
            deletionRequests = JSON.parse(storedRequests);
            
            // Trouver et mettre à jour la demande
            const requestIndex = deletionRequests.findIndex(req => req.requestId === requestId);
            if (requestIndex !== -1) {
                deletionRequests[requestIndex].status = status;
                deletionRequests[requestIndex].processedDate = new Date().toISOString();
                
                // Enregistrer les demandes mises à jour
                localStorage.setItem('deletionRequests', JSON.stringify(deletionRequests));
            }
        } catch (error) {
            console.error('Erreur lors de la mise à jour du statut de la demande:', error);
        }
    }
}