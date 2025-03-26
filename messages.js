// Système de gestion des messages pour Tech Shield

document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si l'utilisateur est connecté et a les droits d'administrateur
    if (window.auth && !window.auth.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }
    
    if (window.auth && !window.auth.isAdmin()) {
        // Rediriger vers la page d'accueil si l'utilisateur n'est pas administrateur
        window.location.href = 'index.html';
        return;
    }
    
    // Initialiser la base de données
    if (window.database) {
        window.database.initDatabase();
    }
    
    // Charger les messages
    loadMessages();
    
    // Ajouter les gestionnaires d'événements
    setupEventListeners();
});

// Fonction pour charger et afficher les messages
async function loadMessages() {
    if (!window.database) return;
    
    const messagesContainer = document.getElementById('messagesList');
    if (!messagesContainer) return;
    
    // Afficher un indicateur de chargement
    messagesContainer.innerHTML = '<div class="loading-indicator">Chargement des messages...</div>';
    
    try {
        // Récupérer tous les messages
        const result = await window.database.getAllMessages();
        
        if (result.success && result.messages && result.messages.length > 0) {
            // Trier les messages par date (du plus récent au plus ancien)
            result.messages.sort((a, b) => new Date(b.date) - new Date(a.date));
            
            // Vider le conteneur
            messagesContainer.innerHTML = '';
            
            // Ajouter chaque message au conteneur
            result.messages.forEach(message => {
                const messageElement = createMessageElement(message);
                messagesContainer.appendChild(messageElement);
            });
            
            // Mettre à jour le compteur de messages non lus
            updateUnreadCount(result.messages);
        } else {
            // Aucun message ou erreur
            messagesContainer.innerHTML = '<div class="no-messages">Aucun message à afficher</div>';
        }
    } catch (error) {
        console.error('Erreur lors du chargement des messages:', error);
        messagesContainer.innerHTML = '<div class="error-message">Erreur lors du chargement des messages</div>';
        
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                'Erreur de chargement des messages: ' + error.message
            );
        }
    }
}

// Fonction pour créer un élément de message
function createMessageElement(message) {
    const messageElement = document.createElement('div');
    messageElement.className = 'message-item' + (message.read ? '' : ' unread');
    messageElement.dataset.id = message.id;
    
    // Formater la date
    const date = new Date(message.date);
    const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
    
    // Construire le contenu du message
    messageElement.innerHTML = `
        <div class="message-header">
            <div class="message-info">
                <span class="message-from">${message.email}</span>
                <span class="message-date">${formattedDate}</span>
            </div>
            <div class="message-actions">
                <button class="mark-read-btn" title="Marquer comme lu">
                    <i class="fa fa-check"></i>
                </button>
                <button class="delete-btn" title="Supprimer">
                    <i class="fa fa-trash"></i>
                </button>
            </div>
        </div>
        <div class="message-content">${message.message}</div>
    `;
    
    // Ajouter les gestionnaires d'événements pour les boutons
    const markReadBtn = messageElement.querySelector('.mark-read-btn');
    const deleteBtn = messageElement.querySelector('.delete-btn');
    
    if (markReadBtn) {
        markReadBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            markMessageAsRead(message.id);
        });
    }
    
    if (deleteBtn) {
        deleteBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            deleteMessage(message.id);
        });
    }
    
    // Ajouter un gestionnaire d'événement pour marquer comme lu lors du clic sur le message
    messageElement.addEventListener('click', function() {
        if (!message.read) {
            markMessageAsRead(message.id);
        }
        
        // Afficher/masquer le contenu du message
        const content = this.querySelector('.message-content');
        if (content) {
            content.classList.toggle('expanded');
        }
    });
    
    return messageElement;
}

// Fonction pour marquer un message comme lu
function markMessageAsRead(messageId) {
    if (!window.database) return;
    
    window.database.markMessageAsRead(messageId)
        .then(result => {
            if (result.success) {
                // Mettre à jour l'interface utilisateur
                const messageElement = document.querySelector(`.message-item[data-id="${messageId}"]`);
                if (messageElement) {
                    messageElement.classList.remove('unread');
                }
                
                // Mettre à jour le compteur de messages non lus
                updateUnreadCount();
            }
        })
        .catch(error => {
            console.error('Erreur lors du marquage du message comme lu:', error);
            
            // Enregistrer l'erreur dans les logs de sécurité
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(
                    'système',
                    'localhost',
                    window.securityLogs.LOG_TYPES.ERROR,
                    'Erreur de marquage de message: ' + error.message
                );
            }
        });
}

// Fonction pour supprimer un message
function deleteMessage(messageId) {
    if (!window.database) return;
    
    // Demander confirmation avant de supprimer
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce message ?')) {
        return;
    }
    
    window.database.deleteMessage(messageId)
        .then(result => {
            if (result.success) {
                // Supprimer l'élément de l'interface utilisateur
                const messageElement = document.querySelector(`.message-item[data-id="${messageId}"]`);
                if (messageElement && messageElement.parentNode) {
                    messageElement.parentNode.removeChild(messageElement);
                }
                
                // Mettre à jour le compteur de messages non lus
                updateUnreadCount();
                
                // Vérifier s'il reste des messages
                const messagesContainer = document.getElementById('messagesList');
                if (messagesContainer && messagesContainer.children.length === 0) {
                    messagesContainer.innerHTML = '<div class="no-messages">Aucun message à afficher</div>';
                }
            }
        })
        .catch(error => {
            console.error('Erreur lors de la suppression du message:', error);
            
            // Enregistrer l'erreur dans les logs de sécurité
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(
                    'système',
                    'localhost',
                    window.securityLogs.LOG_TYPES.ERROR,
                    'Erreur de suppression de message: ' + error.message
                );
            }
        });
}

// Fonction pour mettre à jour le compteur de messages non lus
async function updateUnreadCount(messages) {
    const unreadBadge = document.getElementById('unreadBadge');
    if (!unreadBadge) return;
    
    try {
        let unreadCount = 0;
        
        if (messages) {
            // Utiliser les messages déjà chargés
            unreadCount = messages.filter(msg => !msg.read).length;
        } else {
            // Récupérer tous les messages pour compter les non lus
            const result = await window.database.getAllMessages();
            if (result.success && result.messages) {
                unreadCount = result.messages.filter(msg => !msg.read).length;
            }
        }
        
        // Mettre à jour le badge
        if (unreadCount > 0) {
            unreadBadge.textContent = unreadCount;
            unreadBadge.style.display = 'inline-block';
        } else {
            unreadBadge.style.display = 'none';
        }
    } catch (error) {
        console.error('Erreur lors de la mise à jour du compteur de messages non lus:', error);
    }
}

// Fonction pour configurer les gestionnaires d'événements
function setupEventListeners() {
    // Gestionnaire pour le formulaire de contact (si présent sur la page)
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', handleContactFormSubmit);
    }
    
    // Gestionnaire pour le bouton de rafraîchissement des messages
    const refreshBtn = document.getElementById('refreshMessages');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadMessages);
    }
    
    // Gestionnaire pour le bouton de purge manuelle
    const purgeBtn = document.getElementById('purgeMessages');
    if (purgeBtn) {
        purgeBtn.addEventListener('click', purgeOldMessages);
    }
}

// Fonction pour gérer la soumission du formulaire de contact
async function handleContactFormSubmit(e) {
    e.preventDefault();
    
    if (!window.database) return;
    
    const emailInput = document.getElementById('contactEmail');
    const messageInput = document.getElementById('contactMessage');
    const submitBtn = document.querySelector('#contactForm button[type="submit"]');
    const statusMessage = document.getElementById('contactStatus');
    
    if (!emailInput || !messageInput || !submitBtn || !statusMessage) return;
    
    // Désactiver le bouton pendant le traitement
    submitBtn.disabled = true;
    submitBtn.textContent = 'Envoi en cours...';
    
    // Récupérer les valeurs
    const email = emailInput.value.trim();
    const message = messageInput.value.trim();
    
    try {
        // Valider les entrées côté client
        if (!window.database.validateEmail(email)) {
            throw new Error('Adresse email invalide');
        }
        
        if (!window.database.validateMessage(message)) {
            throw new Error('Message invalide ou trop long');
        }
        
        // Ajouter le message
        const result = await window.database.addMessage(email, message);
        
        if (result.success) {
            // Réinitialiser le formulaire
            emailInput.value = '';
            messageInput.value = '';
            
            // Afficher un message de succès
            statusMessage.textContent = 'Message envoyé avec succès !';
            statusMessage.className = 'success-message';
            statusMessage.style.display = 'block';
            
            // Masquer le message après 5 secondes
            setTimeout(() => {
                statusMessage.style.display = 'none';
            }, 5000);
        } else {
            throw new Error(result.error || 'Erreur lors de l\'envoi du message');
        }
    } catch (error) {
        console.error('Erreur lors de l\'envoi du message:', error);
        
        // Afficher un message d'erreur
        statusMessage.textContent = error.message || 'Une erreur est survenue';
        statusMessage.className = 'error-message';
        statusMessage.style.display = 'block';
        
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLoginLog(
                'système',
                'localhost',
                window.securityLogs.LOG_TYPES.ERROR,
                'Erreur d\'envoi de message: ' + error.message
            );
        }
    } finally {
        // Réactiver le bouton
        submitBtn.disabled = false;
        submitBtn.textContent = 'Envoyer';
    }
}

// Fonction pour purger manuellement les anciens messages
function purgeOldMessages() {
    if (!window.database) return;
    
    // Demander confirmation avant de purger
    if (!confirm('Êtes-vous sûr de vouloir purger les anciens messages ? Cette action est irréversible.')) {
        return;
    }
    
    window.database.purgeOldMessages()
        .then(result => {
            if (result.success) {
                // Afficher un message de succès
                alert(`Purge effectuée avec succès. ${result.deletedCount} message(s) supprimé(s).`);
                
                // Recharger les messages
                loadMessages();
            }
        })
        .catch(error => {
            console.error('Erreur lors de la purge des messages:', error);
            alert('Erreur lors de la purge des messages: ' + error.message);
            
            // Enregistrer l'erreur dans les logs de sécurité
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(
                    'système',
                    'localhost',
                    window.securityLogs.LOG_TYPES.ERROR,
                    'Erreur de purge de messages: ' + error.message
                );
            }
        });
}