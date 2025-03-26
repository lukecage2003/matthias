// Configuration avancée pour la liste blanche d'IP de Tech Shield

// Configuration de la liste blanche d'IP
const ipWhitelistConfig = {
    // Activer/désactiver la vérification de la liste blanche
    enabled: true,
    
    // Mode strict: si activé, toutes les IP non listées seront bloquées pour l'administration
    strictMode: true,
    
    // Nombre maximum d'adresses IP dans la liste blanche
    maxEntries: 50,
    
    // Durée de validité des entrées (en jours, 0 = pas d'expiration)
    entryValidityDays: 30,
    
    // Notification par email lors d'une tentative d'accès depuis une IP non autorisée
    notifyOnUnauthorizedAccess: true,
    
    // Nombre de tentatives avant blocage temporaire
    maxFailedAttempts: 5,
    
    // Durée du blocage temporaire (en minutes)
    temporaryBlockDuration: 30,
    
    // Plages d'IP réservées (ne peuvent pas être ajoutées à la liste blanche)
    // Format: début de plage, fin de plage
    reservedRanges: [
        { start: '0.0.0.0', end: '0.255.255.255' },       // Réservé
        { start: '10.0.0.0', end: '10.255.255.255' },      // Privé
        { start: '127.0.0.0', end: '127.255.255.255' },    // Localhost
        { start: '172.16.0.0', end: '172.31.255.255' },    // Privé
        { start: '192.168.0.0', end: '192.168.255.255' }   // Privé
    ],
    
    // Liste des exceptions (IPs toujours autorisées, même en mode strict)
    // Utile pour les adresses d'urgence
    exceptions: [
        { ip: '127.0.0.1', description: 'Localhost', permanent: true }
    ]
};

// Exporter la configuration
window.ipWhitelistConfig = ipWhitelistConfig;