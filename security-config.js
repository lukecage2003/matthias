// Configuration centralisée de sécurité pour Tech Shield

// Configuration principale de sécurité
window.securityConfig = {
    // Version du système de sécurité
    version: '1.0.0',
    
    // Configuration de la liste blanche d'IP
    ipWhitelist: {
        // Activer ou désactiver la liste blanche d'IP
        enabled: true,
        
        // Mode strict: si activé, seules les IP dans la liste blanche sont autorisées pour l'administration
        strictMode: true,
        
        // Nombre maximum d'entrées dans la liste blanche
        maxEntries: 100,
        
        // Durée de validité par défaut des entrées (en jours, 0 = permanent)
        entryValidityDays: 30,
        
        // Nombre maximum de tentatives échouées avant blocage temporaire
        maxFailedAttempts: 5,
        
        // Durée du blocage temporaire (en minutes)
        temporaryBlockDuration: 30,
        
        // Plages d'IP réservées (non autorisées)
        reservedRanges: [
            { start: '10.0.0.0', end: '10.255.255.255', description: 'Réseau privé classe A' },
            { start: '172.16.0.0', end: '172.31.255.255', description: 'Réseau privé classe B' },
            { start: '192.168.0.0', end: '192.168.255.255', description: 'Réseau privé classe C' }
        ],
        
        // Exceptions (toujours autorisées)
        exceptions: [
            { ip: '127.0.0.1', description: 'Localhost', permanent: true }
        ],
        
        // Journalisation des accès
        logging: {
            // Activer la journalisation
            enabled: true,
            
            // Journaliser les accès autorisés
            logAllowed: true,
            
            // Journaliser les accès refusés
            logDenied: true,
            
            // Niveau de détail (1: minimal, 2: standard, 3: détaillé)
            verbosity: 2
        },
        
        // Notifications
        notifications: {
            // Activer les notifications
            enabled: true,
            
            // Notifier en cas d'accès refusé
            notifyOnDenied: true,
            
            // Notifier en cas de tentative d'accès depuis une IP bloquée
            notifyOnBlocked: true,
            
            // Notifier en cas de tentative d'accès depuis une plage d'IP réservée
            notifyOnReserved: true
        }
    },
    
    // Configuration des permissions utilisateurs
    userPermissions: {
        // Rôles disponibles
        roles: {
            'admin': {
                name: 'Administrateur',
                permissions: ['view_logs', 'manage_users', 'manage_whitelist', 'manage_settings', 'export_data', 'view_dashboard', 'manage_events']
            },
            'moderator': {
                name: 'Modérateur',
                permissions: ['view_logs', 'view_dashboard', 'manage_events']
            },
            'user': {
                name: 'Utilisateur',
                permissions: ['view_dashboard']
            },
            'guest': {
                name: 'Invité',
                permissions: []
            }
        },
        
        // Descriptions des permissions
        permissionDescriptions: {
            'view_logs': 'Consulter les journaux de sécurité',
            'manage_users': 'Gérer les utilisateurs (ajouter, modifier, supprimer)',
            'manage_whitelist': 'Gérer la liste blanche d\'adresses IP',
            'manage_settings': 'Modifier les paramètres du système',
            'export_data': 'Exporter les données (logs, utilisateurs, etc.)',
            'view_dashboard': 'Accéder au tableau de bord',
            'manage_events': 'Gérer les événements du calendrier'
        },
        
        // Mapping des pages aux permissions requises
        pagePermissions: {
            'admin.html': 'view_dashboard',
            'logs.html': 'view_logs',
            'users.html': 'manage_users',
            'whitelist.html': 'manage_whitelist',
            'settings.html': 'manage_settings',
            'events.html': 'manage_events'
        }
    },
    
    // Configuration des journaux de sécurité
    securityLogs: {
        // Types de journaux
        logTypes: {
            SUCCESS: 'success',
            FAILURE: 'failure',
            SUSPICIOUS: 'suspicious',
            INFO: 'info',
            WARNING: 'warning',
            CRITICAL: 'critical'
        },
        
        // Configuration des alertes
        alerts: {
            // Nombre de tentatives échouées avant alerte
            failedLoginThreshold: 5,
            
            // Fenêtre de temps pour les tentatives (minutes)
            timeWindowMinutes: 15,
            
            // Durée pendant laquelle l'alerte reste active (minutes)
            alertDurationMinutes: 30
        },
        
        // Configuration de la détection des comportements suspects
        suspiciousActivity: {
            // Seuils de détection
            thresholds: {
                // Nombre de tentatives de connexion échouées avant de considérer l'activité comme suspecte
                failedLoginAttempts: 3,
                
                // Nombre de connexions depuis des pays différents dans un intervalle de temps
                multiCountryLogins: {
                    count: 2,
                    timeWindowHours: 24
                },
                
                // Nombre de connexions depuis des navigateurs différents dans un intervalle de temps
                multiBrowserLogins: {
                    count: 3,
                    timeWindowHours: 12
                },
                
                // Nombre de connexions à des heures inhabituelles (en dehors des heures de bureau)
                oddHourLogins: {
                    count: 2,
                    timeWindowHours: 48,
                    workHoursStart: 8, // 8h00
                    workHoursEnd: 18   // 18h00
                }
            },
            
            // Niveaux de gravité des alertes
            severityLevels: {
                LOW: 'low',
                MEDIUM: 'medium',
                HIGH: 'high',
                CRITICAL: 'critical'
            }
        },
        
        // Configuration de la rétention des logs
        retention: {
            // Durée de conservation des logs (en jours, 0 = illimité)
            days: 90,
            
            // Nombre maximum de logs à conserver (0 = illimité)
            maxEntries: 10000,
            
            // Purger automatiquement les anciens logs
            autoPurge: true
        },
        
        // Configuration de l'exportation des logs
        export: {
            // Formats d'exportation disponibles
            formats: ['json', 'csv', 'pdf'],
            
            // Inclure les détails complets dans l'exportation
            includeDetails: true
        }
    },
    
    // Configuration de l'authentification à deux facteurs
    twoFactorAuth: {
        // Activer l'authentification à deux facteurs
        enabled: true,
        
        // Rendre l'authentification à deux facteurs obligatoire pour les administrateurs
        requiredForAdmin: true,
        
        // Durée de validité du code TOTP (en secondes)
        codeValiditySeconds: 30,
        
        // Nombre de tentatives avant blocage
        maxAttempts: 3
    },
    
    // Configuration de la protection CSRF
    csrfProtection: {
        // Activer la protection CSRF
        enabled: true,
        
        // Durée de validité du jeton (en secondes)
        tokenValiditySeconds: 3600,
        
        // Utiliser des jetons à usage unique
        oneTimeUse: true,
        
        // Configuration des cookies
        cookies: {
            secure: true,       // Cookies uniquement sur HTTPS
            httpOnly: true,     // Cookies inaccessibles via JavaScript
            sameSite: 'strict', // Cookies envoyés uniquement pour les requêtes provenant du même site
            maxAge: 3600        // Durée de vie du cookie (en secondes)
        }
    }
};

// Exporter la configuration
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { securityConfig: window.securityConfig };
}