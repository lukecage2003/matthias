// Système de gestion des permissions utilisateurs pour Tech Shield

// Configuration des rôles et permissions
const userRoles = {
    // Rôle administrateur avec toutes les permissions
    'admin': {
        name: 'Administrateur',
        permissions: ['view_logs', 'manage_users', 'manage_whitelist', 'manage_settings', 'export_data', 'view_dashboard', 'manage_events']
    },
    // Rôle modérateur avec permissions limitées
    'moderator': {
        name: 'Modérateur',
        permissions: ['view_logs', 'view_dashboard', 'manage_events']
    },
    // Rôle utilisateur standard avec permissions minimales
    'user': {
        name: 'Utilisateur',
        permissions: ['view_dashboard']
    },
    // Rôle invité sans permissions
    'guest': {
        name: 'Invité',
        permissions: []
    }
};

// Descriptions des permissions
const permissionDescriptions = {
    'view_logs': 'Consulter les journaux de sécurité',
    'manage_users': 'Gérer les utilisateurs (ajouter, modifier, supprimer)',
    'manage_whitelist': 'Gérer la liste blanche d\'adresses IP',
    'manage_settings': 'Modifier les paramètres du système',
    'export_data': 'Exporter les données (logs, utilisateurs, etc.)',
    'view_dashboard': 'Accéder au tableau de bord',
    'manage_events': 'Gérer les événements du calendrier'
};

// Fonction pour vérifier si un utilisateur a une permission spécifique
function hasPermission(userRole, permission) {
    // Si le rôle n'existe pas, retourner false
    if (!userRoles[userRole]) {
        return false;
    }
    
    // Vérifier si le rôle a la permission demandée
    return userRoles[userRole].permissions.includes(permission);
}

// Fonction pour obtenir toutes les permissions d'un utilisateur
function getUserPermissions(userRole) {
    // Si le rôle n'existe pas, retourner un tableau vide
    if (!userRoles[userRole]) {
        return [];
    }
    
    // Retourner les permissions du rôle
    return userRoles[userRole].permissions;
}

// Fonction pour vérifier si un utilisateur a accès à une page
function canAccessPage(userRole, pageName) {
    // Mapping des pages aux permissions requises
    const pagePermissions = {
        'admin.html': 'view_dashboard',
        'logs.html': 'view_logs',
        'users.html': 'manage_users',
        'whitelist.html': 'manage_whitelist',
        'settings.html': 'manage_settings',
        'events.html': 'manage_events'
    };
    
    // Si la page n'est pas dans la liste, autoriser l'accès par défaut
    if (!pagePermissions[pageName]) {
        return true;
    }
    
    // Vérifier si l'utilisateur a la permission requise
    return hasPermission(userRole, pagePermissions[pageName]);
}

// Fonction pour protéger une page en fonction des permissions
function protectPage(pageName) {
    // Vérifier si l'utilisateur est connecté
    if (!window.auth || !window.auth.isAuthenticated()) {
        window.location.href = 'login.html';
        return false;
    }
    
    // Obtenir le rôle de l'utilisateur
    const userRole = sessionStorage.getItem('userRole') || 'guest';
    
    // Vérifier si l'utilisateur a accès à la page
    if (!canAccessPage(userRole, pageName)) {
        // Rediriger vers une page d'erreur ou la page d'accueil
        window.location.href = 'unauthorized.html';
        return false;
    }
    
    return true;
}

// Fonction pour obtenir la liste des rôles disponibles
function getAvailableRoles() {
    const roles = {};
    
    for (const role in userRoles) {
        roles[role] = {
            name: userRoles[role].name,
            permissionCount: userRoles[role].permissions.length
        };
    }
    
    return roles;
}

// Fonction pour obtenir la description d'une permission
function getPermissionDescription(permission) {
    return permissionDescriptions[permission] || permission;
}

// Fonction pour obtenir toutes les descriptions de permissions
function getAllPermissionDescriptions() {
    return permissionDescriptions;
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.userPermissions = {
    hasPermission,
    getUserPermissions,
    canAccessPage,
    protectPage,
    getAvailableRoles,
    getPermissionDescription,
    getAllPermissionDescriptions
};