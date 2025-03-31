// Module de gestion des permissions sécurisées pour Tech Shield
// Implémentation du principe du moindre privilège

/**
 * Configuration du système de permissions
 */
const securePermissionsConfig = {
    // Activer la vérification stricte des permissions
    strictMode: true,
    
    // Journaliser les vérifications de permissions
    logPermissionChecks: true,
    
    // Rôle par défaut pour les utilisateurs non authentifiés
    defaultRole: 'guest',
    
    // Rôle par défaut pour les nouveaux utilisateurs
    defaultUserRole: 'user',
    
    // Activer la séparation des privilèges
    enablePrivilegeSeparation: true,
    
    // Activer la révocation automatique des sessions lors des changements de permissions
    autoRevokeOnPermissionChange: true
};

/**
 * Définition des rôles et permissions avec séparation des privilèges
 * Implémentation du principe du moindre privilège
 */
const secureRoles = {
    // Rôle super administrateur (accès complet)
    'super_admin': {
        name: 'Super Administrateur',
        description: 'Accès complet au système',
        permissions: [
            'admin.access',
            'admin.users.manage',
            'admin.roles.manage',
            'admin.permissions.manage',
            'admin.whitelist.manage',
            'admin.settings.manage',
            'admin.logs.view',
            'admin.logs.export',
            'admin.logs.delete',
            'admin.events.manage',
            'admin.security.manage',
            'admin.system.manage'
        ],
        ipRestriction: true, // Restreint aux IPs de la liste blanche
        twoFactorRequired: true // 2FA obligatoire
    },
    
    // Rôle administrateur (accès limité)
    'admin': {
        name: 'Administrateur',
        description: 'Gestion des utilisateurs et des paramètres',
        permissions: [
            'admin.access',
            'admin.users.manage',
            'admin.whitelist.view',
            'admin.settings.view',
            'admin.settings.edit',
            'admin.logs.view',
            'admin.events.manage',
            'admin.security.view'
        ],
        ipRestriction: true, // Restreint aux IPs de la liste blanche
        twoFactorRequired: true // 2FA obligatoire
    },
    
    // Rôle responsable sécurité
    'security_officer': {
        name: 'Responsable Sécurité',
        description: 'Gestion de la sécurité et des logs',
        permissions: [
            'admin.access',
            'admin.whitelist.manage',
            'admin.logs.view',
            'admin.logs.export',
            'admin.security.manage'
        ],
        ipRestriction: true, // Restreint aux IPs de la liste blanche
        twoFactorRequired: true // 2FA obligatoire
    },
    
    // Rôle modérateur (permissions limitées)
    'moderator': {
        name: 'Modérateur',
        description: 'Gestion des événements et visualisation des logs',
        permissions: [
            'admin.access',
            'admin.logs.view',
            'admin.events.manage',
            'admin.events.view'
        ],
        ipRestriction: false,
        twoFactorRequired: false
    },
    
    // Rôle utilisateur standard (permissions minimales)
    'user': {
        name: 'Utilisateur',
        description: 'Accès standard au site',
        permissions: [
            'site.access',
            'events.view'
        ],
        ipRestriction: false,
        twoFactorRequired: false
    },
    
    // Rôle invité (sans permissions)
    'guest': {
        name: 'Invité',
        description: 'Accès public limité',
        permissions: [
            'site.access'
        ],
        ipRestriction: false,
        twoFactorRequired: false
    }
};

/**
 * Descriptions détaillées des permissions
 */
const permissionDescriptions = {
    // Permissions d'administration générale
    'admin.access': 'Accéder au panneau d\'administration',
    'admin.users.manage': 'Gérer les utilisateurs (ajouter, modifier, supprimer)',
    'admin.users.view': 'Voir la liste des utilisateurs',
    'admin.roles.manage': 'Gérer les rôles et permissions',
    'admin.permissions.manage': 'Modifier les permissions des utilisateurs',
    
    // Permissions de liste blanche
    'admin.whitelist.manage': 'Gérer la liste blanche d\'adresses IP',
    'admin.whitelist.view': 'Voir la liste blanche d\'adresses IP',
    
    // Permissions de paramètres
    'admin.settings.manage': 'Gérer tous les paramètres système',
    'admin.settings.view': 'Voir les paramètres système',
    'admin.settings.edit': 'Modifier les paramètres de base',
    
    // Permissions de logs
    'admin.logs.view': 'Consulter les journaux de sécurité',
    'admin.logs.export': 'Exporter les journaux de sécurité',
    'admin.logs.delete': 'Supprimer des entrées de journaux',
    
    // Permissions d'événements
    'admin.events.manage': 'Gérer les événements (ajouter, modifier, supprimer)',
    'admin.events.view': 'Voir les événements',
    
    // Permissions de sécurité
    'admin.security.manage': 'Gérer les paramètres de sécurité',
    'admin.security.view': 'Voir les paramètres de sécurité',
    
    // Permissions système
    'admin.system.manage': 'Gérer les paramètres système avancés',
    
    // Permissions de site
    'site.access': 'Accéder au site public',
    'events.view': 'Voir les événements publics'
};

/**
 * Mapping des pages aux permissions requises
 */
const pagePermissions = {
    // Pages d'administration
    'admin.html': 'admin.access',
    'admin-users.html': 'admin.users.view',
    'admin-roles.html': 'admin.roles.manage',
    'admin-whitelist.html': 'admin.whitelist.view',
    'admin-settings.html': 'admin.settings.view',
    'admin-logs.html': 'admin.logs.view',
    'admin-events.html': 'admin.events.view',
    'admin-security.html': 'admin.security.view',
    
    // Pages publiques
    'index.html': 'site.access',
    'events.html': 'events.view'
};

/**
 * Initialise le système de permissions sécurisées
 * @param {Object} config - Configuration optionnelle
 * @returns {boolean} - Succès de l'initialisation
 */
function initSecurePermissions(config = {}) {
    try {
        // Fusionner la configuration fournie avec la configuration par défaut
        Object.assign(securePermissionsConfig, config);
        
        console.log('Système de permissions sécurisées initialisé');
        
        // Journaliser l'initialisation si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: 'Système de permissions sécurisées initialisé',
                source: 'secure-permissions'
            });
        }
        
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'initialisation du système de permissions:', error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: 'Échec de l\'initialisation du système de permissions: ' + error.message,
                source: 'secure-permissions'
            });
        }
        
        return false;
    }
}

/**
 * Vérifie si un utilisateur a une permission spécifique
 * @param {string} userRole - Rôle de l'utilisateur
 * @param {string} permission - Permission à vérifier
 * @returns {boolean} - True si l'utilisateur a la permission
 */
function hasPermission(userRole, permission) {
    try {
        // Si le rôle n'existe pas, retourner false
        if (!secureRoles[userRole]) {
            logPermissionCheck(userRole, permission, false, 'Rôle inexistant');
            return false;
        }
        
        // Vérifier si le rôle a la permission demandée
        const hasPermission = secureRoles[userRole].permissions.includes(permission);
        
        // Journaliser la vérification
        logPermissionCheck(userRole, permission, hasPermission);
        
        return hasPermission;
    } catch (error) {
        console.error('Erreur lors de la vérification de permission:', error);
        
        // En cas d'erreur, refuser l'accès par sécurité
        logPermissionCheck(userRole, permission, false, 'Erreur: ' + error.message);
        return false;
    }
}

/**
 * Vérifie si un utilisateur a toutes les permissions spécifiées
 * @param {string} userRole - Rôle de l'utilisateur
 * @param {Array<string>} permissions - Liste des permissions à vérifier
 * @returns {boolean} - True si l'utilisateur a toutes les permissions
 */
function hasAllPermissions(userRole, permissions) {
    if (!Array.isArray(permissions) || permissions.length === 0) {
        return true; // Aucune permission requise
    }
    
    return permissions.every(permission => hasPermission(userRole, permission));
}

/**
 * Vérifie si un utilisateur a au moins une des permissions spécifiées
 * @param {string} userRole - Rôle de l'utilisateur
 * @param {Array<string>} permissions - Liste des permissions à vérifier
 * @returns {boolean} - True si l'utilisateur a au moins une permission
 */
function hasAnyPermission(userRole, permissions) {
    if (!Array.isArray(permissions) || permissions.length === 0) {
        return false; // Aucune permission spécifiée
    }
    
    return permissions.some(permission => hasPermission(userRole, permission));
}

/**
 * Obtient toutes les permissions d'un utilisateur
 * @param {string} userRole - Rôle de l'utilisateur
 * @returns {Array<string>} - Liste des permissions
 */
function getUserPermissions(userRole) {
    // Si le rôle n'existe pas, retourner un tableau vide
    if (!secureRoles[userRole]) {
        return [];
    }
    
    // Retourner les permissions du rôle
    return [...secureRoles[userRole].permissions];
}

/**
 * Vérifie si un utilisateur a accès à une page
 * @param {string} userRole - Rôle de l'utilisateur
 * @param {string} pageName - Nom de la page
 * @returns {boolean} - True si l'utilisateur a accès
 */
function canAccessPage(userRole, pageName) {
    // Si la page n'est pas dans la liste, vérifier si le mode strict est activé
    if (!pagePermissions[pageName]) {
        // En mode strict, refuser l'accès aux pages non répertoriées
        if (securePermissionsConfig.strictMode) {
            logPermissionCheck(userRole, 'page:' + pageName, false, 'Page non répertoriée (mode strict)');
            return false;
        }
        // Sinon, autoriser l'accès par défaut
        return true;
    }
    
    // Vérifier si l'utilisateur a la permission requise
    return hasPermission(userRole, pagePermissions[pageName]);
}

/**
 * Protège une page en fonction des permissions
 * @param {string} pageName - Nom de la page
 * @returns {boolean} - True si l'accès est autorisé
 */
function protectPage(pageName) {
    try {
        // Vérifier si l'utilisateur est connecté
        if (!window.auth || !window.auth.isAuthenticated()) {
            // Rediriger vers la page de connexion
            window.location.href = 'login.html?redirect=' + encodeURIComponent(window.location.pathname);
            return false;
        }
        
        // Obtenir le rôle de l'utilisateur
        const userRole = sessionStorage.getItem('userRole') || securePermissionsConfig.defaultRole;
        
        // Vérifier si l'authentification à deux facteurs est requise pour ce rôle
        if (secureRoles[userRole] && secureRoles[userRole].twoFactorRequired) {
            // Vérifier si l'utilisateur a complété l'authentification à deux facteurs
            if (!sessionStorage.getItem('twoFactorAuthenticated')) {
                // Rediriger vers la page de 2FA
                window.location.href = 'twofa.html?redirect=' + encodeURIComponent(window.location.pathname);
                return false;
            }
        }
        
        // Vérifier si la restriction d'IP est activée pour ce rôle
        if (secureRoles[userRole] && secureRoles[userRole].ipRestriction) {
            // Vérifier si l'IP est dans la liste blanche
            if (window.ipWhitelist && !window.ipWhitelist.checkIPAccess().allowed) {
                // Rediriger vers une page d'erreur
                window.location.href = 'unauthorized.html?reason=ip';
                return false;
            }
        }
        
        // Vérifier si l'utilisateur a accès à la page
        if (!canAccessPage(userRole, pageName)) {
            // Rediriger vers une page d'erreur
            window.location.href = 'unauthorized.html?reason=permission';
            return false;
        }
        
        return true;
    } catch (error) {
        console.error('Erreur lors de la protection de page:', error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: 'Erreur lors de la protection de page: ' + error.message,
                source: 'secure-permissions',
                metadata: { page: pageName }
            });
        }
        
        // En cas d'erreur, rediriger vers la page d'erreur par sécurité
        window.location.href = 'error.html';
        return false;
    }
}

/**
 * Journalise une vérification de permission
 * @param {string} userRole - Rôle de l'utilisateur
 * @param {string} permission - Permission vérifiée
 * @param {boolean} granted - Accès accordé ou refusé
 * @param {string} reason - Raison du refus (optionnel)
 */
function logPermissionCheck(userRole, permission, granted, reason = '') {
    // Ne journaliser que si la configuration le permet
    if (!securePermissionsConfig.logPermissionChecks) {
        return;
    }
    
    // Journaliser si le module de logs est disponible
    if (window.securityLogs) {
        const logType = granted ? window.securityLogs.LOG_TYPES.INFO : window.securityLogs.LOG_TYPES.WARNING;
        const details = granted 
            ? `Permission '${permission}' accordée au rôle '${userRole}'`
            : `Permission '${permission}' refusée au rôle '${userRole}'${reason ? ' - ' + reason : ''}`;
        
        window.securityLogs.addLog({
            status: logType,
            details: details,
            source: 'secure-permissions',
            metadata: {
                userRole,
                permission,
                granted,
                reason,
                url: window.location.href
            }
        });
    }
}

/**
 * Obtient la description d'une permission
 * @param {string} permission - Nom de la permission
 * @returns {string} - Description de la permission
 */
function getPermissionDescription(permission) {
    return permissionDescriptions[permission] || 'Permission non documentée';
}

/**
 * Obtient tous les rôles disponibles
 * @returns {Object} - Objet contenant tous les rôles
 */
function getAllRoles() {
    return {...secureRoles};
}

/**
 * Obtient toutes les permissions disponibles avec leurs descriptions
 * @returns {Object} - Objet contenant toutes les permissions
 */
function getAllPermissions() {
    return {...permissionDescriptions};
}

// Exposer les fonctions publiques
window.securePermissions = {
    init: initSecurePermissions,
    hasPermission,
    hasAllPermissions,
    hasAnyPermission,
    getUserPermissions,
    canAccessPage,
    protectPage,
    getPermissionDescription,
    getAllRoles,
    getAllPermissions
};