// Module d'intégration des systèmes de sécurité pour Tech Shield

document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si la configuration de sécurité centralisée est disponible
    if (!window.securityConfig) {
        console.warn('Configuration de sécurité non trouvée, utilisation des paramètres par défaut');
        return;
    }
    
    // Initialiser tous les modules de sécurité
    initSecurityModules();
    
    /**
     * Initialise tous les modules de sécurité avec la configuration centralisée
     */
    function initSecurityModules() {
        // Initialiser la liste blanche d'IP
        initIPWhitelist();
        
        // Initialiser les permissions utilisateurs
        initUserPermissions();
        
        // Initialiser les journaux de sécurité
        initSecurityLogs();
        
        // Initialiser l'authentification à deux facteurs
        initTwoFactorAuth();
        
        // Initialiser la protection CSRF
        initCSRFProtection();
        
        // Protéger les formulaires contre les attaques CSRF
        if (window.csrf && window.csrf.protectForms) {
            window.csrf.protectForms();
        }
        
        // Initialiser le module de journalisation avancée
        if (window.securityLogs && window.securityLogs.init) {
            window.securityLogs.init();
        }
        
        // Ajouter un gestionnaire d'événements pour les tentatives de connexion
        addLoginEventHandler();
    }
    
    /**
     * Initialise la liste blanche d'IP avec la configuration centralisée
     */
    function initIPWhitelist() {
        if (!window.ipWhitelist) return;
        
        // Appliquer la configuration centralisée
        const ipConfig = window.securityConfig.ipWhitelist;
        
        // Mettre à jour la configuration de la liste blanche d'IP
        window.ipWhitelistConfig = {
            enabled: ipConfig.enabled,
            strictMode: ipConfig.strictMode,
            maxEntries: ipConfig.maxEntries,
            entryValidityDays: ipConfig.entryValidityDays,
            maxFailedAttempts: ipConfig.maxFailedAttempts,
            temporaryBlockDuration: ipConfig.temporaryBlockDuration,
            reservedRanges: ipConfig.reservedRanges,
            exceptions: ipConfig.exceptions,
            notifyOnUnauthorizedAccess: ipConfig.notifications.notifyOnDenied
        };
    }
    
    /**
     * Initialise les permissions utilisateurs avec la configuration centralisée
     */
    function initUserPermissions() {
        if (!window.userPermissions) return;
        
        // Appliquer la configuration centralisée
        const permConfig = window.securityConfig.userPermissions;
        
        // Mettre à jour les rôles et permissions
        window.userRoles = permConfig.roles;
        window.permissionDescriptions = permConfig.permissionDescriptions;
        
        // Ajouter une fonction pour vérifier les permissions de page
        window.checkPagePermission = function(pageName, userRole) {
            const pagePermissions = permConfig.pagePermissions;
            if (!pagePermissions[pageName]) return true;
            
            return window.userPermissions.hasPermission(userRole, pagePermissions[pageName]);
        };
    }
    
    /**
     * Initialise les journaux de sécurité avec la configuration centralisée
     */
    function initSecurityLogs() {
        if (!window.securityLogs) return;
        
        // Appliquer la configuration centralisée
        const logsConfig = window.securityConfig.securityLogs;
        
        // Mettre à jour les types de journaux
        window.securityLogs.LOG_TYPES = logsConfig.logTypes;
        
        // Mettre à jour la configuration des alertes
        window.securityLogs.securityAlertConfig = {
            failedLoginThreshold: logsConfig.alerts.failedLoginThreshold,
            timeWindowMinutes: logsConfig.alerts.timeWindowMinutes,
            alertDurationMinutes: logsConfig.alerts.alertDurationMinutes
        };
        
        // Configurer la rétention des logs
        window.securityLogs.retentionConfig = {
            days: logsConfig.retention.days,
            maxEntries: logsConfig.retention.maxEntries,
            autoPurge: logsConfig.retention.autoPurge
        };
        
        // Ajouter une fonction pour purger les anciens logs
        window.securityLogs.purgeOldLogs = function() {
            if (!this.retentionConfig.autoPurge) return;
            
            const logs = this.getAllLogs();
            const now = new Date();
            const cutoffDate = new Date(now.getTime() - (this.retentionConfig.days * 24 * 60 * 60 * 1000));
            
            const filteredLogs = logs.filter(log => new Date(log.timestamp) >= cutoffDate);
            
            // Limiter le nombre de logs si nécessaire
            if (this.retentionConfig.maxEntries > 0 && filteredLogs.length > this.retentionConfig.maxEntries) {
                filteredLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                filteredLogs.length = this.retentionConfig.maxEntries;
            }
            
            // Mettre à jour les logs
            window.securityLogs.securityLogs = filteredLogs;
            window.securityLogs.saveLogsToStorage();
        };
        
        // Purger les anciens logs au démarrage
        window.securityLogs.purgeOldLogs();
    }
    
    /**
     * Initialise l'authentification à deux facteurs avec la configuration centralisée
     */
    function initTwoFactorAuth() {
        if (!window.twoFA) return;
        
        // Appliquer la configuration centralisée
        const twoFAConfig = window.securityConfig.twoFactorAuth;
        
        // Mettre à jour la configuration 2FA
        window.twoFA.config = {
            enabled: twoFAConfig.enabled,
            requiredForAdmin: twoFAConfig.requiredForAdmin,
            codeValiditySeconds: twoFAConfig.codeValiditySeconds,
            maxAttempts: twoFAConfig.maxAttempts
        };
        
        // Ajouter une fonction pour vérifier si 2FA est requis pour un utilisateur
        window.twoFA.isRequired = function(email, role) {
            if (!this.config.enabled) return false;
            if (role === 'admin' && this.config.requiredForAdmin) return true;
            return this.isTwoFAEnabled(email);
        };
    }
    
    /**
     * Initialise la protection CSRF avec la configuration centralisée
     */
    function initCSRFProtection() {
        if (!window.csrf) return;
        
        // Vérifier si la configuration CSRF existe
        if (!window.securityConfig || !window.securityConfig.csrfProtection) {
            console.warn('Configuration CSRF non trouvée, utilisation des paramètres par défaut');
            return;
        }
        
        // Appliquer la configuration centralisée
        const csrfConfig = window.securityConfig.csrfProtection;
        
        // Mettre à jour la configuration des cookies
        if (csrfConfig.cookies) {
            window.cookieConfig = csrfConfig.cookies;
        }
        
        // Ajouter une fonction pour protéger tous les formulaires
        window.csrf.protectForms = function() {
            // Vérifier si la protection CSRF est activée
            if (csrfConfig && typeof csrfConfig.enabled !== 'undefined' && !csrfConfig.enabled) return;
            
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                window.csrf.addCSRFTokenToForm(form);
            });
        };
    }
    
    /**
     * Ajoute un gestionnaire d'événements pour les tentatives de connexion
     */
    function addLoginEventHandler() {
        const loginForm = document.getElementById('loginForm');
        if (!loginForm) return;
        
        // Ajouter un gestionnaire pour le formulaire de connexion
        loginForm.addEventListener('submit', function(e) {
            // Ne pas empêcher la soumission du formulaire ici, car cela est géré ailleurs
            
            const email = document.getElementById('loginEmail').value.trim();
            const password = document.getElementById('loginPassword').value;
            
            // Obtenir l'adresse IP du client (simulée ici)
            const clientIP = window.ipWhitelist ? window.ipWhitelist.getClientIP() : '127.0.0.1';
            
            // Vérifier si l'IP est autorisée pour l'administration
            if (email.endsWith('@admin.com') || email === 'admin@techshield.com') {
                if (window.ipWhitelist && window.securityConfig.ipWhitelist.strictMode) {
                    const ipAccess = window.ipWhitelist.checkIPAccess();
                    if (!ipAccess.allowed) {
                        // Journaliser la tentative d'accès non autorisée
                        if (window.securityLogs) {
                            window.securityLogs.addLoginLog(
                                email, 
                                clientIP, 
                                window.securityLogs.LOG_TYPES.SUSPICIOUS, 
                                'Tentative d\'accès admin depuis une IP non autorisée'
                            );
                        }
                    }
                }
            }
            
            // Journaliser la tentative de connexion (le résultat sera journalisé par auth.js)
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(
                    email, 
                    clientIP, 
                    window.securityLogs.LOG_TYPES.INFO, 
                    'Tentative de connexion'
                );
            }
        });
    }
});