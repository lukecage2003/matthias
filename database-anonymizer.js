// Module d'anonymisation et de suppression des données pour Tech Shield

/**
 * Ce module étend les fonctionnalités du module database.js
 * pour permettre l'anonymisation et la suppression des données personnelles
 * conformément aux exigences du RGPD
 */

// Vérifier si le module de base de données est disponible
if (!window.database) {
    console.error('Module de base de données non disponible');
}

/**
 * Supprime les messages d'un utilisateur par son email
 * @param {string} email - L'adresse email de l'utilisateur
 * @returns {Object} - Résultat de l'opération
 */
function deleteMessagesByEmail(email) {
    if (!email) {
        console.error('Email non spécifié pour la suppression');
        return { success: false, error: 'Email non spécifié' };
    }
    
    try {
        // Récupérer les messages
        const result = window.database.getAllMessages();
        if (!result.success || !result.messages || !result.messages.length) {
            return { success: true, message: 'Aucun message à supprimer' };
        }
        
        const messages = result.messages;
        
        // Filtrer les messages pour exclure ceux de l'utilisateur spécifié
        const filteredMessages = messages.filter(message => message.email !== email);
        
        // Calculer le nombre de messages supprimés
        const deletedCount = messages.length - filteredMessages.length;
        
        // Mettre à jour la base de données
        // Dans un environnement de production, cette opération serait effectuée côté serveur
        window.messagesDB = filteredMessages;
        
        // Sauvegarder les messages dans le localStorage
        localStorage.setItem('messages', JSON.stringify(filteredMessages));
        
        // Journaliser l'opération de suppression
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: `Suppression des messages pour un utilisateur: ${deletedCount} messages supprimés`,
                source: 'rgpd-module'
            });
        }
        
        return { 
            success: true, 
            message: `${deletedCount} messages supprimés avec succès`, 
            count: deletedCount 
        };
    } catch (error) {
        console.error('Erreur lors de la suppression des messages:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Anonymise les messages d'un utilisateur par son email
 * @param {string} email - L'adresse email de l'utilisateur
 * @returns {Object} - Résultat de l'opération
 */
function anonymizeMessagesByEmail(email) {
    if (!email) {
        console.error('Email non spécifié pour l\'anonymisation');
        return { success: false, error: 'Email non spécifié' };
    }
    
    try {
        // Récupérer les messages
        const result = window.database.getAllMessages();
        if (!result.success || !result.messages || !result.messages.length) {
            return { success: true, message: 'Aucun message à anonymiser' };
        }
        
        const messages = result.messages;
        
        // Compter les messages concernés
        const messagesToAnonymize = messages.filter(message => message.email === email);
        
        // Anonymiser les messages
        let anonymizedCount = 0;
        
        messages.forEach((message, index) => {
            if (message.email === email) {
                // Anonymiser l'email
                if (window.dataAnonymizer && window.dataAnonymizer.anonymizeEmail) {
                    messages[index].email = window.dataAnonymizer.anonymizeEmail(email);
                } else {
                    // Méthode de secours si le module d'anonymisation n'est pas disponible
                    const [username, domain] = email.split('@');
                    messages[index].email = username.charAt(0) + '*'.repeat(username.length - 2) + username.charAt(username.length - 1) + '@' + domain;
                }
                
                // Anonymiser le contenu du message si présent
                if (message.content) {
                    messages[index].content = '[Contenu anonymisé conformément au RGPD]';
                }
                
                // Ajouter une note indiquant que le message a été anonymisé
                messages[index].anonymized = true;
                messages[index].anonymizedAt = new Date().toISOString();
                
                anonymizedCount++;
            }
        });
        
        // Mettre à jour la base de données
        window.messagesDB = messages;
        
        // Sauvegarder les messages dans le localStorage
        localStorage.setItem('messages', JSON.stringify(messages));
        
        // Journaliser l'opération d'anonymisation
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: `Anonymisation des messages pour un utilisateur: ${anonymizedCount} messages anonymisés`,
                source: 'rgpd-module'
            });
        }
        
        return { 
            success: true, 
            message: `${anonymizedCount} messages anonymisés avec succès`, 
            count: anonymizedCount 
        };
    } catch (error) {
        console.error('Erreur lors de l\'anonymisation des messages:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Supprime le compte d'un utilisateur et toutes ses données associées
 * @param {string} email - L'adresse email de l'utilisateur
 * @returns {Object} - Résultat de l'opération
 */
function deleteUserAccount(email) {
    if (!email) {
        console.error('Email non spécifié pour la suppression du compte');
        return { success: false, error: 'Email non spécifié' };
    }
    
    try {
        let success = true;
        const results = {};
        
        // 1. Supprimer le compte utilisateur
        if (window.auth && window.auth.removeUser) {
            const authResult = window.auth.removeUser(email);
            results.auth = authResult;
            success = success && authResult.success;
        }
        
        // 2. Supprimer les messages de l'utilisateur
        const messagesResult = deleteMessagesByEmail(email);
        results.messages = messagesResult;
        success = success && messagesResult.success;
        
        // 3. Supprimer ou anonymiser les logs de l'utilisateur
        if (window.securityLogs) {
            if (window.securityLogs.deleteLogsByEmail) {
                const logsResult = window.securityLogs.deleteLogsByEmail(email);
                results.logs = logsResult;
                success = success && logsResult.success;
            } else if (window.securityLogs.anonymizeLogsByEmail) {
                const logsResult = window.securityLogs.anonymizeLogsByEmail(email);
                results.logs = logsResult;
                success = success && logsResult.success;
            }
        }
        
        // 4. Supprimer les données de comportement utilisateur si présentes
        if (window.loginSecurity && window.loginSecurity.clearUserData) {
            const behaviorResult = window.loginSecurity.clearUserData(email);
            results.behavior = behaviorResult;
            success = success && behaviorResult.success;
        }
        
        // 5. Supprimer les données 2FA si présentes
        if (window.twoFA && window.twoFA.removeUserSecret) {
            const twoFAResult = window.twoFA.removeUserSecret(email);
            results.twoFA = twoFAResult;
            success = success && twoFAResult.success;
        }
        
        // Journaliser l'opération de suppression du compte
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: `Suppression du compte utilisateur: ${email}`,
                source: 'rgpd-module'
            });
        }
        
        return { 
            success: success, 
            message: success ? 'Compte utilisateur supprimé avec succès' : 'Erreurs lors de la suppression du compte', 
            results: results 
        };
    } catch (error) {
        console.error('Erreur lors de la suppression du compte:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Exporte les données d'un utilisateur au format JSON (droit à la portabilité)
 * @param {string} email - L'adresse email de l'utilisateur
 * @returns {Object} - Résultat de l'opération avec les données exportées
 */
function exportUserData(email) {
    if (!email) {
        console.error('Email non spécifié pour l\'exportation des données');
        return { success: false, error: 'Email non spécifié' };
    }
    
    try {
        const userData = {
            email: email,
            exportDate: new Date().toISOString(),
            account: null,
            messages: [],
            logs: []
        };
        
        // 1. Récupérer les données du compte
        if (window.auth && window.auth.getUserData) {
            userData.account = window.auth.getUserData(email);
            // Supprimer les données sensibles comme le mot de passe
            if (userData.account && userData.account.password) {
                delete userData.account.password;
            }
        }
        
        // 2. Récupérer les messages de l'utilisateur
        const messagesResult = window.database.getAllMessages();
        if (messagesResult.success && messagesResult.messages) {
            userData.messages = messagesResult.messages.filter(message => message.email === email);
        }
        
        // 3. Récupérer les logs de l'utilisateur
        if (window.securityLogs && window.securityLogs.getAllLogs) {
            const logs = window.securityLogs.getAllLogs();
            userData.logs = logs.filter(log => log.email === email);
        }
        
        // Journaliser l'opération d'exportation
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: `Exportation des données utilisateur: ${email}`,
                source: 'rgpd-module'
            });
        }
        
        return { 
            success: true, 
            message: 'Données utilisateur exportées avec succès', 
            data: userData 
        };
    } catch (error) {
        console.error('Erreur lors de l\'exportation des données:', error);
        return { success: false, error: error.message };
    }
}

// Étendre le module de base de données avec les fonctions RGPD
if (window.database) {
    window.database.deleteMessagesByEmail = deleteMessagesByEmail;
    window.database.anonymizeMessagesByEmail = anonymizeMessagesByEmail;
    window.database.deleteUserAccount = deleteUserAccount;
    window.database.exportUserData = exportUserData;
    
    console.log('Module RGPD pour la base de données initialisé');
}