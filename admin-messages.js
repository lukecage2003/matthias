/**
 * Module de gestion de l'interface d'administration des messages pour Tech Shield
 */

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

/**
 * Charge et affiche les messages
 * @param {Object} filters - Filtres à appliquer aux messages
 */
async function loadMessages(filters = {}) {
    if (!window.database) return;
    
    const messagesContainer = document.getElementById('messagesList');
    if (!messagesContainer) return;
    
    // Afficher un indicateur de chargement
    messagesContainer.innerHTML = '<div class="loading-indicator">Chargement des messages...</div>';
    
    try {
        // Récupérer tous les messages avec les filtres appliqués
        const result = await window.database.getAllMessages(filters);
        
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
            
            // Mettre à jour les statistiques
            updateMessageStats(result.messages);
        } else {
            // Aucun message ou erreur
            messagesContainer.innerHTML = '<div class="no-messages">Aucun message à afficher</div>';
            
            // Réinitialiser les statistiques
            updateMessageStats([]);
        }
    } catch (error) {
        console.error('Erreur lors du chargement des messages:', error);
        messagesContainer.innerHTML = '<div class="error-message">Erreur lors du chargement des messages</div>';
        
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLog({
                action: 'Erreur',
                details: 'Erreur de chargement des messages: ' + error.message,
                status: window.securityLogs.LOG_TYPES.ERROR
            });
        }
    }
}

/**
 * Crée un élément HTML pour un message
 * @param {Object} message - Le message à afficher
 * @returns {HTMLElement} - L'élément HTML du message
 */
function createMessageElement(message) {
    const messageElement = document.createElement('div');
    messageElement.className = 'message-item' + (message.read ? '' : ' unread');
    messageElement.dataset.id = message.id;
    
    // Extraire le nom de l'expéditeur du message si disponible
    let senderName = message.email;
    const nameMatch = message.message.match(/De:\s*([^\n]+)/);
    if (nameMatch && nameMatch[1]) {
        senderName = nameMatch[1];
    }
    
    // Formater la date
    const date = new Date(message.date);
    const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
    
    // Extraire le contenu du message
    let messageContent = message.message;
    const contentMatch = message.message.match(/Message:\s*([\s\S]+)/);
    if (contentMatch && contentMatch[1]) {
        messageContent = contentMatch[1].trim();
    }
    
    // Construire le contenu du message
    messageElement.innerHTML = `
        <div class="message-header">
            <div class="message-info">
                <span class="message-from">${senderName}</span>
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
        <div class="message-content">${messageContent}</div>
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

/**
 * Marque un message comme lu
 * @param {string} messageId - L'identifiant du message
 */
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
                
                // Mettre à jour les statistiques
                updateMessageStats();
            }
        })
        .catch(error => {
            console.error('Erreur lors du marquage du message comme lu:', error);
            
            // Enregistrer l'erreur dans les logs de sécurité
            if (window.securityLogs) {
                window.securityLogs.addLog({
                    action: 'Erreur',
                    details: 'Erreur de marquage de message: ' + error.message,
                    status: window.securityLogs.LOG_TYPES.ERROR
                });
            }
        });
}

/**
 * Supprime un message
 * @param {string} messageId - L'identifiant du message
 */
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
                
                // Mettre à jour les statistiques
                updateMessageStats();
                
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
                window.securityLogs.addLog({
                    action: 'Erreur',
                    details: 'Erreur de suppression de message: ' + error.message,
                    status: window.securityLogs.LOG_TYPES.ERROR
                });
            }
        });
}

/**
 * Met à jour les statistiques des messages
 * @param {Array} messages - Liste des messages (optionnel)
 */
async function updateMessageStats(messages) {
    const totalCountElement = document.getElementById('totalMessages');
    const unreadCountElement = document.getElementById('unreadMessages');
    
    if (!totalCountElement && !unreadCountElement) return;
    
    try {
        let totalCount = 0;
        let unreadCount = 0;
        
        if (messages) {
            // Utiliser les messages déjà chargés
            totalCount = messages.length;
            unreadCount = messages.filter(msg => !msg.read).length;
        } else {
            // Récupérer tous les messages pour compter
            const result = await window.database.getAllMessages();
            if (result.success && result.messages) {
                totalCount = result.messages.length;
                unreadCount = result.messages.filter(msg => !msg.read).length;
            }
        }
        
        // Mettre à jour les compteurs
        if (totalCountElement) totalCountElement.textContent = totalCount;
        if (unreadCountElement) unreadCountElement.textContent = unreadCount;
    } catch (error) {
        console.error('Erreur lors de la mise à jour des statistiques:', error);
    }
}

/**
 * Configure les gestionnaires d'événements
 */
function setupEventListeners() {
    // Gestionnaire pour le bouton de rafraîchissement des messages
    const refreshBtn = document.getElementById('refreshMessages');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => loadMessages());
    }
    
    // Gestionnaire pour le formulaire de filtrage
    const filterForm = document.getElementById('messageFilterForm');
    if (filterForm) {
        filterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Récupérer les valeurs des filtres
            const filters = {
                searchText: document.getElementById('searchText')?.value || '',
                read: document.getElementById('readFilter')?.value || undefined,
                startDate: document.getElementById('startDate')?.value || undefined,
                endDate: document.getElementById('endDate')?.value || undefined
            };
            
            // Charger les messages avec les filtres
            loadMessages(filters);
        });
    }
    
    // Gestionnaire pour le bouton de réinitialisation des filtres
    const resetFilterBtn = document.getElementById('resetFilters');
    if (resetFilterBtn) {
        resetFilterBtn.addEventListener('click', function() {
            // Réinitialiser le formulaire de filtrage
            if (filterForm) filterForm.reset();
            
            // Recharger tous les messages sans filtre
            loadMessages();
        });
    }
    
    // Gestionnaire pour le bouton d'exportation des messages
    const exportBtn = document.getElementById('exportMessages');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportMessages);
    }
}

/**
 * Exporte les messages au format CSV
 */
async function exportMessages() {
    if (!window.database) return;
    
    try {
        // Récupérer tous les messages
        const result = await window.database.getAllMessages();
        
        if (!result.success || !result.messages || result.messages.length === 0) {
            alert('Aucun message à exporter');
            return;
        }
        
        // Créer le contenu CSV
        let csvContent = 'Date,Email,Message,Lu\n';
        
        result.messages.forEach(message => {
            // Formater la date
            const date = new Date(message.date).toLocaleString();
            
            // Échapper les virgules et les guillemets dans les champs
            const email = `"${message.email.replace(/"/g, '""')}"`;  
            const messageText = `"${message.message.replace(/"/g, '""')}"`;  
            const read = message.read ? 'Oui' : 'Non';
            
            // Ajouter la ligne au CSV
            csvContent += `${date},${email},${messageText},${read}\n`;
        });
        
        // Créer un objet Blob pour le téléchargement
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        
        // Créer un lien de téléchargement
        const link = document.createElement('a');
        link.setAttribute('href', url);
        link.setAttribute('download', `messages_${new Date().toISOString().slice(0, 10)}.csv`);
        link.style.display = 'none';
        
        // Ajouter le lien au document et cliquer dessus
        document.body.appendChild(link);
        link.click();
        
        // Nettoyer
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        // Enregistrer l'action dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLog({
                action: 'Export',
                details: `Export de ${result.messages.length} messages au format CSV`,
                status: window.securityLogs.LOG_TYPES.INFO
            });
        }
    } catch (error) {
        console.error('Erreur lors de l\'exportation des messages:', error);
        alert('Erreur lors de l\'exportation des messages: ' + error.message);
        
        // Enregistrer l'erreur dans les logs de sécurité
        if (window.securityLogs) {
            window.securityLogs.addLog({
                action: 'Erreur',
                details: 'Erreur d\'exportation des messages: ' + error.message,
                status: window.securityLogs.LOG_TYPES.ERROR
            });
        }
    }
}