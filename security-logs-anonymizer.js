// Module d'anonymisation des logs de sécurité pour Tech Shield

/**
 * Ce module étend les fonctionnalités du module security-logs.js
 * pour permettre l'anonymisation des données personnelles dans les logs
 * conformément aux exigences du RGPD
 */

// Vérifier si le module de logs de sécurité est disponible
if (!window.securityLogs) {
    console.error('Module de logs de sécurité non disponible');
}

/**
 * Anonymise les logs de sécurité pour un email spécifique
 * @param {string} email - L'adresse email à anonymiser dans les logs
 * @returns {Object} - Résultat de l'opération
 */
function anonymizeLogsByEmail(email) {
    if (!email) {
        console.error('Email non spécifié pour l\'anonymisation');
        return { success: false, error: 'Email non spécifié' };
    }
    
    try {
        // Récupérer les logs
        const logs = window.securityLogs.getAllLogs();
        if (!logs || !logs.length) {
            return { success: true, message: 'Aucun log à anonymiser' };
        }
        
        // Compter les logs concernés
        const logsToAnonymize = logs.filter(log => log.email === email);
        
        // Anonymiser les logs
        let anonymizedCount = 0;
        
        logs.forEach((log, index) => {
            if (log.email === email) {
                // Anonymiser l'email
                if (window.dataAnonymizer && window.dataAnonymizer.anonymizeEmail) {
                    logs[index].email = window.dataAnonymizer.anonymizeEmail(email);
                } else {
                    // Méthode de secours si le module d'anonymisation n'est pas disponible
                    const [username, domain] = email.split('@');
                    logs[index].email = username.charAt(0) + '*'.repeat(username.length - 2) + username.charAt(username.length - 1) + '@' + domain;
                }
                
                // Anonymiser l'adresse IP si elle est présente
                if (log.ipAddress) {
                    if (window.dataAnonymizer && window.dataAnonymizer.anonymizeIP) {
                        logs[index].ipAddress = window.dataAnonymizer.anonymizeIP(log.ipAddress);
                    } else {
                        // Méthode de secours
                        const ipParts = log.ipAddress.split('.');
                        if (ipParts.length === 4) {
                            logs[index].ipAddress = `${ipParts[0]}.${ipParts[1]}.xxx.xxx`;
                        }
                    }
                }
                
                // Ajouter une note indiquant que le log a été anonymisé
                logs[index].anonymized = true;
                logs[index].anonymizedAt = new Date().toISOString();
                
                anonymizedCount++;
            }
        });
        
        // Sauvegarder les logs modifiés
        window.securityLogs.saveLogs(logs);
        
        // Journaliser l'opération d'anonymisation
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: `Anonymisation des logs pour un utilisateur: ${anonymizedCount} logs anonymisés`,
            source: 'rgpd-module'
        });
        
        return { 
            success: true, 
            message: `${anonymizedCount} logs anonymisés avec succès`, 
            count: anonymizedCount 
        };
    } catch (error) {
        console.error('Erreur lors de l\'anonymisation des logs:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Anonymise les logs de sécurité pour une adresse IP spécifique
 * @param {string} ipAddress - L'adresse IP à anonymiser dans les logs
 * @returns {Object} - Résultat de l'opération
 */
function anonymizeLogsByIP(ipAddress) {
    if (!ipAddress) {
        console.error('Adresse IP non spécifiée pour l\'anonymisation');
        return { success: false, error: 'Adresse IP non spécifiée' };
    }
    
    try {
        // Récupérer les logs
        const logs = window.securityLogs.getAllLogs();
        if (!logs || !logs.length) {
            return { success: true, message: 'Aucun log à anonymiser' };
        }
        
        // Compter les logs concernés
        const logsToAnonymize = logs.filter(log => log.ipAddress === ipAddress);
        
        // Anonymiser les logs
        let anonymizedCount = 0;
        
        logs.forEach((log, index) => {
            if (log.ipAddress === ipAddress) {
                // Anonymiser l'adresse IP
                if (window.dataAnonymizer && window.dataAnonymizer.anonymizeIP) {
                    logs[index].ipAddress = window.dataAnonymizer.anonymizeIP(ipAddress);
                } else {
                    // Méthode de secours
                    const ipParts = ipAddress.split('.');
                    if (ipParts.length === 4) {
                        logs[index].ipAddress = `${ipParts[0]}.${ipParts[1]}.xxx.xxx`;
                    }
                }
                
                // Ajouter une note indiquant que le log a été anonymisé
                logs[index].anonymized = true;
                logs[index].anonymizedAt = new Date().toISOString();
                
                anonymizedCount++;
            }
        });
        
        // Sauvegarder les logs modifiés
        window.securityLogs.saveLogs(logs);
        
        // Journaliser l'opération d'anonymisation
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: `Anonymisation des logs pour une adresse IP: ${anonymizedCount} logs anonymisés`,
            source: 'rgpd-module'
        });
        
        return { 
            success: true, 
            message: `${anonymizedCount} logs anonymisés avec succès`, 
            count: anonymizedCount 
        };
    } catch (error) {
        console.error('Erreur lors de l\'anonymisation des logs:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Anonymise tous les logs plus anciens qu'une certaine date
 * @param {Date|string} date - Date limite (les logs plus anciens seront anonymisés)
 * @returns {Object} - Résultat de l'opération
 */
function anonymizeOldLogs(date) {
    if (!date) {
        // Par défaut, anonymiser les logs de plus d'un an
        const oneYearAgo = new Date();
        oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
        date = oneYearAgo;
    } else if (typeof date === 'string') {
        date = new Date(date);
    }
    
    try {
        // Récupérer les logs
        const logs = window.securityLogs.getAllLogs();
        if (!logs || !logs.length) {
            return { success: true, message: 'Aucun log à anonymiser' };
        }
        
        // Anonymiser les logs
        let anonymizedCount = 0;
        
        logs.forEach((log, index) => {
            const logDate = new Date(log.timestamp);
            
            if (logDate < date && !log.anonymized) {
                // Anonymiser l'email
                if (log.email && log.email !== 'système') {
                    if (window.dataAnonymizer && window.dataAnonymizer.anonymizeEmail) {
                        logs[index].email = window.dataAnonymizer.anonymizeEmail(log.email);
                    } else {
                        // Méthode de secours
                        const [username, domain] = log.email.split('@');
                        logs[index].email = username.charAt(0) + '*'.repeat(username.length - 2) + username.charAt(username.length - 1) + '@' + domain;
                    }
                }
                
                // Anonymiser l'adresse IP
                if (log.ipAddress) {
                    if (window.dataAnonymizer && window.dataAnonymizer.anonymizeIP) {
                        logs[index].ipAddress = window.dataAnonymizer.anonymizeIP(log.ipAddress);
                    } else {
                        // Méthode de secours
                        const ipParts = log.ipAddress.split('.');
                        if (ipParts.length === 4) {
                            logs[index].ipAddress = `${ipParts[0]}.${ipParts[1]}.xxx.xxx`;
                        }
                    }
                }
                
                // Anonymiser l'agent utilisateur
                if (log.userAgent) {
                    logs[index].userAgent = 'anonymized';
                }
                
                // Ajouter une note indiquant que le log a été anonymisé
                logs[index].anonymized = true;
                logs[index].anonymizedAt = new Date().toISOString();
                
                anonymizedCount++;
            }
        });
        
        // Sauvegarder les logs modifiés
        window.securityLogs.saveLogs(logs);
        
        // Journaliser l'opération d'anonymisation
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: `Anonymisation automatique des logs anciens: ${anonymizedCount} logs anonymisés`,
            source: 'rgpd-module'
        });
        
        return { 
            success: true, 
            message: `${anonymizedCount} logs anciens anonymisés avec succès`, 
            count: anonymizedCount 
        };
    } catch (error) {
        console.error('Erreur lors de l\'anonymisation des logs anciens:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Supprime définitivement les logs d'un utilisateur
 * @param {string} email - L'adresse email de l'utilisateur
 * @returns {Object} - Résultat de l'opération
 */
function deleteLogsByEmail(email) {
    if (!email) {
        console.error('Email non spécifié pour la suppression');
        return { success: false, error: 'Email non spécifié' };
    }
    
    try {
        // Récupérer les logs
        const logs = window.securityLogs.getAllLogs();
        if (!logs || !logs.length) {
            return { success: true, message: 'Aucun log à supprimer' };
        }
        
        // Filtrer les logs pour exclure ceux de l'utilisateur spécifié
        const filteredLogs = logs.filter(log => log.email !== email);
        
        // Calculer le nombre de logs supprimés
        const deletedCount = logs.length - filteredLogs.length;
        
        // Sauvegarder les logs filtrés
        window.securityLogs.saveLogs(filteredLogs);
        
        // Journaliser l'opération de suppression
        window.securityLogs.addLog({
            status: window.securityLogs.LOG_TYPES.INFO,
            details: `Suppression des logs pour un utilisateur: ${deletedCount} logs supprimés`,
            source: 'rgpd-module'
        });
        
        return { 
            success: true, 
            message: `${deletedCount} logs supprimés avec succès`, 
            count: deletedCount 
        };
    } catch (error) {
        console.error('Erreur lors de la suppression des logs:', error);
        return { success: false, error: error.message };
    }
}

// Étendre le module de logs de sécurité avec les fonctions d'anonymisation
if (window.securityLogs) {
    window.securityLogs.anonymizeLogsByEmail = anonymizeLogsByEmail;
    window.securityLogs.anonymizeLogsByIP = anonymizeLogsByIP;
    window.securityLogs.anonymizeOldLogs = anonymizeOldLogs;
    window.securityLogs.deleteLogsByEmail = deleteLogsByEmail;
    
    console.log('Module d\'anonymisation des logs de sécurité initialisé');
}