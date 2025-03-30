// Module de journalisation avancée pour la détection des connexions suspectes

/**
 * Module de logs de sécurité avancés pour Tech Shield
 * Ce module étend les fonctionnalités de base de security-logs.js avec des
 * capacités avancées de détection des activités suspectes.
 */

// Stockage des données d'analyse
let userLoginPatterns = {};
let ipLoginPatterns = {};
let suspiciousActivities = [];

// Configuration des seuils de détection
const detectionConfig = {
    // Seuils pour les tentatives multiples
    failedAttempts: {
        threshold: 3,           // Nombre de tentatives échouées avant détection
        timeWindowMinutes: 15   // Fenêtre de temps pour les tentatives (minutes)
    },
    
    // Seuils pour les connexions à des heures inhabituelles
    unusualHours: {
        startHour: 22,          // Heure de début de la période inhabituelle (22h)
        endHour: 6,             // Heure de fin de la période inhabituelle (6h)
        minLoginCount: 5        // Nombre minimum de connexions pour établir un modèle
    },
    
    // Seuils pour les changements d'emplacement
    locationChange: {
        timeWindowHours: 24,     // Fenêtre de temps pour les changements (heures)
        distanceThreshold: 500   // Distance minimale pour considérer un changement (km)
    },
    
    // Seuils pour les connexions depuis plusieurs appareils
    multiDeviceLogin: {
        timeWindowHours: 1,      // Fenêtre de temps pour les connexions (heures)
        deviceCount: 3           // Nombre d'appareils différents avant détection
    }
};

/**
 * Initialise le module de logs avancés
 */
function init() {
    // Charger les données depuis le stockage local
    loadPatterns();
    
    // S'abonner aux événements de connexion si le module de base est disponible
    if (window.securityLogs) {
        window.securityLogs.subscribeToLoginEvents(analyzeLoginEvent);
        console.log('Module de logs de sécurité avancés initialisé');
    } else {
        console.error('Module de logs de base non disponible, impossible d\'initialiser les logs avancés');
    }
}

/**
 * Analyse un événement de connexion pour détecter des activités suspectes
 * @param {Object} log - Log de connexion à analyser
 */
function analyzeLoginEvent(log) {
    // Ne pas analyser les logs système
    if (!log.email || log.email === 'système') return;
    
    // Mettre à jour les modèles de connexion
    updateLoginPatterns(log);
    
    // Effectuer les différentes analyses
    detectMultipleFailedAttempts(log);
    detectUnusualLoginHours(log);
    detectLocationChange(log);
    detectMultiDeviceLogin(log);
    
    // Sauvegarder les modèles mis à jour
    savePatterns();
}

/**
 * Met à jour les modèles de connexion pour un utilisateur
 * @param {Object} log - Log de connexion
 */
function updateLoginPatterns(log) {
    const email = log.email;
    const timestamp = new Date(log.timestamp);
    const hour = timestamp.getHours();
    const userAgent = log.userAgent;
    const ipAddress = log.ipAddress;
    
    // Initialiser le modèle utilisateur s'il n'existe pas
    if (!userLoginPatterns[email]) {
        userLoginPatterns[email] = {
            loginTimes: [],          // Heures de connexion
            loginDays: [],           // Jours de connexion
            devices: {},             // Appareils utilisés
            ips: {},                 // IPs utilisées
            locations: [],           // Emplacements de connexion
            lastLogin: null,         // Dernière connexion
            failedAttempts: []       // Tentatives échouées
        };
    }
    
    // Initialiser le modèle IP s'il n'existe pas
    if (!ipLoginPatterns[ipAddress]) {
        ipLoginPatterns[ipAddress] = {
            users: {},               // Utilisateurs connectés depuis cette IP
            loginTimes: [],          // Heures de connexion
            failedAttempts: [],      // Tentatives échouées
            successfulLogins: []     // Connexions réussies
        };
    }
    
    // Mettre à jour le modèle utilisateur
    const userPattern = userLoginPatterns[email];
    
    // Ajouter l'heure de connexion
    userPattern.loginTimes.push({
        timestamp: timestamp.toISOString(),
        hour: hour,
        day: timestamp.getDay()
    });
    
    // Limiter à 100 entrées
    if (userPattern.loginTimes.length > 100) {
        userPattern.loginTimes.shift();
    }
    
    // Ajouter le jour de connexion s'il n'existe pas déjà
    const day = timestamp.getDay();
    if (!userPattern.loginDays.includes(day)) {
        userPattern.loginDays.push(day);
    }
    
    // Mettre à jour les appareils
    if (!userPattern.devices[userAgent]) {
        userPattern.devices[userAgent] = {
            firstSeen: timestamp.toISOString(),
            lastSeen: timestamp.toISOString(),
            count: 1
        };
    } else {
        userPattern.devices[userAgent].lastSeen = timestamp.toISOString();
        userPattern.devices[userAgent].count++;
    }
    
    // Mettre à jour les IPs
    if (!userPattern.ips[ipAddress]) {
        userPattern.ips[ipAddress] = {
            firstSeen: timestamp.toISOString(),
            lastSeen: timestamp.toISOString(),
            count: 1
        };
    } else {
        userPattern.ips[ipAddress].lastSeen = timestamp.toISOString();
        userPattern.ips[ipAddress].count++;
    }
    
    // Ajouter la tentative échouée si applicable
    if (log.status === window.securityLogs.LOG_TYPES.FAILURE) {
        userPattern.failedAttempts.push({
            timestamp: timestamp.toISOString(),
            ipAddress: ipAddress,
            userAgent: userAgent
        });
        
        // Limiter à 50 entrées
        if (userPattern.failedAttempts.length > 50) {
            userPattern.failedAttempts.shift();
        }
    }
    
    // Mettre à jour la dernière connexion
    userPattern.lastLogin = {
        timestamp: timestamp.toISOString(),
        ipAddress: ipAddress,
        userAgent: userAgent,
        status: log.status
    };
    
    // Mettre à jour le modèle IP
    const ipPattern = ipLoginPatterns[ipAddress];
    
    // Ajouter l'utilisateur s'il n'existe pas déjà
    if (!ipPattern.users[email]) {
        ipPattern.users[email] = {
            firstSeen: timestamp.toISOString(),
            lastSeen: timestamp.toISOString(),
            count: 1
        };
    } else {
        ipPattern.users[email].lastSeen = timestamp.toISOString();
        ipPattern.users[email].count++;
    }
    
    // Ajouter l'heure de connexion
    ipPattern.loginTimes.push({
        timestamp: timestamp.toISOString(),
        hour: hour,
        day: timestamp.getDay(),
        email: email
    });
    
    // Limiter à 100 entrées
    if (ipPattern.loginTimes.length > 100) {
        ipPattern.loginTimes.shift();
    }
    
    // Ajouter la tentative échouée ou réussie
    if (log.status === window.securityLogs.LOG_TYPES.FAILURE) {
        ipPattern.failedAttempts.push({
            timestamp: timestamp.toISOString(),
            email: email,
            userAgent: userAgent
        });
        
        // Limiter à 50 entrées
        if (ipPattern.failedAttempts.length > 50) {
            ipPattern.failedAttempts.shift();
        }
    } else if (log.status === window.securityLogs.LOG_TYPES.SUCCESS) {
        ipPattern.successfulLogins.push({
            timestamp: timestamp.toISOString(),
            email: email,
            userAgent: userAgent
        });
        
        // Limiter à 50 entrées
        if (ipPattern.successfulLogins.length > 50) {
            ipPattern.successfulLogins.shift();
        }
    }
}

/**
 * Détecte les tentatives multiples de connexion échouées
 * @param {Object} log - Log de connexion
 */
function detectMultipleFailedAttempts(log) {
    // Ne vérifier que les échecs de connexion
    if (log.status !== window.securityLogs.LOG_TYPES.FAILURE) return;
    
    const email = log.email;
    const ipAddress = log.ipAddress;
    const now = new Date(log.timestamp);
    const timeWindow = detectionConfig.failedAttempts.timeWindowMinutes * 60 * 1000; // en ms
    
    // Vérifier les tentatives échouées récentes pour cet utilisateur
    if (userLoginPatterns[email]) {
        const recentFailures = userLoginPatterns[email].failedAttempts.filter(attempt => {
            const attemptTime = new Date(attempt.timestamp);
            return (now - attemptTime) <= timeWindow;
        });
        
        if (recentFailures.length >= detectionConfig.failedAttempts.threshold) {
            // Créer une activité suspecte
            const activity = {
                id: generateUniqueId(),
                timestamp: now.toISOString(),
                type: 'multiple_failed_attempts',
                email: email,
                ipAddress: ipAddress,
                details: `${recentFailures.length} tentatives de connexion échouées en ${detectionConfig.failedAttempts.timeWindowMinutes} minutes`,
                severity: 'high',
                data: {
                    attempts: recentFailures,
                    threshold: detectionConfig.failedAttempts.threshold,
                    timeWindow: detectionConfig.failedAttempts.timeWindowMinutes
                }
            };
            
            // Ajouter l'activité suspecte et notifier
            addSuspiciousActivity(activity);
        }
    }
    
    // Vérifier les tentatives échouées récentes pour cette IP
    if (ipLoginPatterns[ipAddress]) {
        const recentFailures = ipLoginPatterns[ipAddress].failedAttempts.filter(attempt => {
            const attemptTime = new Date(attempt.timestamp);
            return (now - attemptTime) <= timeWindow;
        });
        
        if (recentFailures.length >= detectionConfig.failedAttempts.threshold) {
            // Créer une activité suspecte
            const activity = {
                id: generateUniqueId(),
                timestamp: now.toISOString(),
                type: 'multiple_failed_attempts_ip',
                email: 'multiple',
                ipAddress: ipAddress,
                details: `${recentFailures.length} tentatives de connexion échouées depuis l'IP ${ipAddress} en ${detectionConfig.failedAttempts.timeWindowMinutes} minutes`,
                severity: 'high',
                data: {
                    attempts: recentFailures,
                    threshold: detectionConfig.failedAttempts.threshold,
                    timeWindow: detectionConfig.failedAttempts.timeWindowMinutes
                }
            };
            
            // Ajouter l'activité suspecte et notifier
            addSuspiciousActivity(activity);
        }
    }
}

/**
 * Détecte les connexions à des heures inhabituelles
 * @param {Object} log - Log de connexion
 */
function detectUnusualLoginHours(log) {
    // Ne vérifier que les connexions réussies
    if (log.status !== window.securityLogs.LOG_TYPES.SUCCESS) return;
    
    const email = log.email;
    const timestamp = new Date(log.timestamp);
    const hour = timestamp.getHours();
    
    // Vérifier si l'heure est inhabituelle
    const isUnusualHour = (hour >= detectionConfig.unusualHours.startHour || 
                          hour < detectionConfig.unusualHours.endHour);
    
    if (!isUnusualHour) return;
    
    // Vérifier si l'utilisateur a suffisamment de connexions pour établir un modèle
    if (userLoginPatterns[email] && userLoginPatterns[email].loginTimes.length >= detectionConfig.unusualHours.minLoginCount) {
        // Calculer les heures habituelles de connexion
        const loginHours = userLoginPatterns[email].loginTimes.map(login => login.hour);
        const hourCounts = {};
        
        loginHours.forEach(h => {
            hourCounts[h] = (hourCounts[h] || 0) + 1;
        });
        
        // Calculer le pourcentage de connexions à cette heure
        const currentHourCount = hourCounts[hour] || 0;
        const hourPercentage = (currentHourCount / loginHours.length) * 100;
        
        // Si moins de 10% des connexions sont à cette heure, c'est inhabituel
        if (hourPercentage < 10) {
            // Créer une activité suspecte
            const activity = {
                id: generateUniqueId(),
                timestamp: timestamp.toISOString(),
                type: 'unusual_login_hour',
                email: email,
                ipAddress: log.ipAddress,
                details: `Connexion à une heure inhabituelle (${hour}h00) pour l'utilisateur ${email}`,
                severity: 'medium',
                data: {
                    hour: hour,
                    hourPercentage: hourPercentage,
                    userAgent: log.userAgent
                }
            };
            
            // Ajouter l'activité suspecte et notifier
            addSuspiciousActivity(activity);
        }
    }
}

/**
 * Détecte les changements d'emplacement rapides
 * @param {Object} log - Log de connexion
 */
function detectLocationChange(log) {
    // Ne vérifier que les connexions réussies
    if (log.status !== window.securityLogs.LOG_TYPES.SUCCESS) return;
    
    const email = log.email;
    const ipAddress = log.ipAddress;
    const timestamp = new Date(log.timestamp);
    
    // Vérifier si l'utilisateur a une connexion précédente
    if (userLoginPatterns[email] && userLoginPatterns[email].lastLogin) {
        const lastLogin = userLoginPatterns[email].lastLogin;
        const lastLoginTime = new Date(lastLogin.timestamp);
        const lastIp = lastLogin.ipAddress;
        
        // Ne vérifier que si l'IP est différente et que la connexion précédente est récente
        if (lastIp !== ipAddress && 
            (timestamp - lastLoginTime) <= (detectionConfig.locationChange.timeWindowHours * 60 * 60 * 1000)) {
            
            // Dans un environnement réel, on utiliserait un service de géolocalisation
            // Pour cette démonstration, on simule un changement d'emplacement
            const simulatedDistance = Math.random() * 1000; // Distance simulée en km
            
            if (simulatedDistance >= detectionConfig.locationChange.distanceThreshold) {
                // Créer une activité suspecte
                const activity = {
                    id: generateUniqueId(),
                    timestamp: timestamp.toISOString(),
                    type: 'rapid_location_change',
                    email: email,
                    ipAddress: ipAddress,
                    details: `Changement d'emplacement rapide pour ${email} (${lastIp} → ${ipAddress})`,
                    severity: 'high',
                    data: {
                        previousIp: lastIp,
                        currentIp: ipAddress,
                        timeDifference: (timestamp - lastLoginTime) / (60 * 1000), // en minutes
                        simulatedDistance: Math.round(simulatedDistance)
                    }
                };
                
                // Ajouter l'activité suspecte et notifier
                addSuspiciousActivity(activity);
            }
        }
    }
}

/**
 * Détecte les connexions depuis plusieurs appareils dans un court laps de temps
 * @param {Object} log - Log de connexion
 */
function detectMultiDeviceLogin(log) {
    // Ne vérifier que les connexions réussies
    if (log.status !== window.securityLogs.LOG_TYPES.SUCCESS) return;
    
    const email = log.email;
    const userAgent = log.userAgent;
    const timestamp = new Date(log.timestamp);
    const timeWindow = detectionConfig.multiDeviceLogin.timeWindowHours * 60 * 60 * 1000; // en ms
    
    // Vérifier si l'utilisateur a des connexions précédentes
    if (userLoginPatterns[email] && userLoginPatterns[email].loginTimes.length > 1) {
        // Récupérer les connexions récentes
        const recentLogins = userLoginPatterns[email].loginTimes.filter(login => {
            const loginTime = new Date(login.timestamp);
            return (timestamp - loginTime) <= timeWindow;
        });
        
        // Compter les appareils uniques dans la fenêtre de temps
        const uniqueDevices = new Set();
        recentLogins.forEach(login => {
            // Dans un environnement réel, on récupérerait l'agent utilisateur associé à cette connexion
            // Pour cette démonstration, on utilise l'agent utilisateur actuel
            uniqueDevices.add(userAgent);
        });
        
        // Ajouter l'appareil actuel s'il n'est pas déjà compté
        uniqueDevices.add(userAgent);
        
        if (uniqueDevices.size >= detectionConfig.multiDeviceLogin.deviceCount) {
            // Créer une activité suspecte
            const activity = {
                id: generateUniqueId(),
                timestamp: timestamp.toISOString(),
                type: 'multi_device_login',
                email: email,
                ipAddress: log.ipAddress,
                details: `Connexions depuis ${uniqueDevices.size} appareils différents en ${detectionConfig.multiDeviceLogin.timeWindowHours}h pour ${email}`,
                severity: 'medium',
                data: {
                    deviceCount: uniqueDevices.size,
                    timeWindow: detectionConfig.multiDeviceLogin.timeWindowHours
                }
            };
            
            // Ajouter l'activité suspecte et notifier
            addSuspiciousActivity(activity);
        }
    }
}

/**
 * Ajoute une activité suspecte et notifie les administrateurs
 * @param {Object} activity - Activité suspecte à ajouter
 */
function addSuspiciousActivity(activity) {
    // Vérifier si une activité similaire existe déjà récemment
    const existingSimilarActivity = suspiciousActivities.find(a => 
        a.type === activity.type && 
        a.email === activity.email && 
        a.ipAddress === activity.ipAddress &&
        (new Date(activity.timestamp) - new Date(a.timestamp)) < (30 * 60 * 1000) // 30 minutes
    );
    
    if (existingSimilarActivity) {
        // Mettre à jour l'activité existante au lieu d'en créer une nouvelle
        existingSimilarActivity.timestamp = activity.timestamp;
        existingSimilarActivity.count = (existingSimilarActivity.count || 1) + 1;
        existingSimilarActivity.details = activity.details;
        existingSimilarActivity.data = activity.data;
    } else {
        // Ajouter la nouvelle activité
        activity.count = 1;
        suspiciousActivities.push(activity);
        
        // Limiter à 100 activités
        if (suspiciousActivities.length > 100) {
            suspiciousActivities.shift();
        }
        
        // Créer une alerte de sécurité si le module de base est disponible
        if (window.securityLogs) {
            window.securityLogs.createSecurityAlert(
                `Activité suspecte: ${activity.type}`,
                activity.details,
                window.securityLogs.LOG_TYPES.SUSPICIOUS,
                {
                    email: activity.email,
                    ipAddress: activity.ipAddress,
                    activityType: activity.type,
                    severity: activity.severity,
                    data: activity.data
                }
            );
            
            // Ajouter un log de sécurité
            window.securityLogs.addLoginLog(
                activity.email,
                activity.ipAddress,
                window.securityLogs.LOG_TYPES.SUSPICIOUS,
                activity.details,
                {
                    activityType: activity.type,
                    severity: activity.severity,
                    data: activity.data
                }
            );
        }
    }
    
    // Sauvegarder les activités suspectes
    saveActivities();
}

/**
 * Détecte les activités suspectes pour un utilisateur
 * @param {string} email - Email de l'utilisateur
 * @returns {Array} Liste des activités suspectes
 */
function detectSuspiciousActivity(email) {
    // Filtrer les activités suspectes pour cet utilisateur
    return suspiciousActivities.filter(activity => activity.email === email);
}

/**
 * Génère un rapport de sécurité pour un utilisateur
 * @param {string} email - Email de l'utilisateur
 * @returns {Object} Rapport de sécurité
 */
function generateSecurityReport(email) {
    // Vérifier si l'utilisateur existe
    if (!userLoginPatterns[email]) {
        return {
            email: email,
            timestamp: new Date().toISOString(),
            status: 'no_data',
            message: 'Aucune donnée disponible pour cet utilisateur'
        };
    }
    
    const userPattern = userLoginPatterns[email];
    
    // Calculer les statistiques
    const loginCount = userPattern.loginTimes.length;
    const uniqueIPs = Object.keys(userPattern.ips).length;
    const uniqueDevices = Object.keys(userPattern.devices).length;
    const failedAttempts = userPattern.failedAttempts.length;
    
    // Calculer les heures habituelles de connexion
    const loginHours = userPattern.loginTimes.map(login => login.hour);
    const hourCounts = {};
    
    loginHours.forEach(h => {
        hourCounts[h] = (hourCounts[h] || 0) + 1;
    });
    
    // Trouver les heures les plus fréquentes
    const sortedHours = Object.entries(hourCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([hour, count]) => ({
            hour: parseInt(hour),
            count: count,
            percentage: Math.round((count / loginCount) * 100)
        }));
    
    // Trouver les appareils les plus utilisés
    const sortedDevices = Object.entries(userPattern.devices)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 3)
        .map(([device, data]) => ({
            device: device,
            count: data.count,
            percentage: Math.round((data.count / loginCount) * 100)
        }));
    
    // Trouver les IPs les plus utilisées
    const sortedIPs = Object.entries(userPattern.ips)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 3)
        .map(([ip, data]) => ({
            ip: ip,
            count: data.count,
            percentage: Math.round((data.count / loginCount) * 100)
        }));
    
    // Activités suspectes récentes
    const recentSuspiciousActivities = suspiciousActivities
        .filter(activity => activity.email === email)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 5);
    
    // Générer le rapport
    return {
        email: email,
        timestamp: new Date().toISOString(),
        status: 'generated',
        statistics: {
            loginCount: loginCount,
            uniqueIPs: uniqueIPs,
            uniqueDevices: uniqueDevices,
            failedAttempts: failedAttempts
        },
        patterns: {
            commonHours: sortedHours,
            commonDevices: sortedDevices,
            commonIPs: sortedIPs,
            loginDays: userPattern.loginDays.map(day => {
                const days = ['Dimanche', 'Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];
                return days[day];
            })
        },
        suspiciousActivities: recentSuspiciousActivities,
        riskLevel: calculateRiskLevel(email)
    };
}

/**
 * Calcule le niveau de risque pour un utilisateur
 * @param {string} email - Email de l'utilisateur
 * @returns {string} Niveau de risque (low, medium, high)
 */
function calculateRiskLevel(email) {
    // Compter les activités suspectes récentes
    const recentActivities = suspiciousActivities.filter(activity => {
        return activity.email === email && 
               (new Date() - new Date(activity.timestamp)) < (7 * 24 * 60 * 60 * 1000); // 7 jours
    });
    
    const highSeverityCount = recentActivities.filter(a => a.severity === 'high').length;
    const mediumSeverityCount = recentActivities.filter(a => a.severity === 'medium').length;
    
    if (highSeverityCount >= 2 || (highSeverityCount >= 1 && mediumSeverityCount >= 2)) {
        return 'high';
    } else if (highSeverityCount >= 1 || mediumSeverityCount >= 2) {
        return 'medium';
    } else {
        return 'low';
    }
}

/**
 * Notifie l'administrateur des activités suspectes
 * @param {Array} activities - Liste des activités suspectes
 */
function notifyAdmin(activities) {
    if (!activities || activities.length === 0) return;
    
    // Dans un environnement réel, on enverrait une notification par email ou SMS
    // Pour cette démonstration, on affiche une notification dans la console
    console.warn(`[ALERTE] ${activities.length} activités suspectes détectées:`);
    
    activities.forEach(activity => {
        console.warn(`- ${activity.details} (${activity.severity})`);
    });
    
    // Si le module de base est disponible, créer une alerte
    if (window.securityLogs && activities.length > 0) {
        const highSeverityActivities = activities.filter(a => a.severity === 'high');
        
        if (highSeverityActivities.length > 0) {
            window.securityLogs.createSecurityAlert(
                `${highSeverityActivities.length} activités à haut risque détectées`,
                `Plusieurs activités suspectes à haut risque ont été détectées. Veuillez vérifier le tableau de bord de sécurité.`,
                window.securityLogs.LOG_TYPES.WARNING,
                { activities: highSeverityActivities }
            );
        }
    }
}

/**
 * Sauvegarde les modèles de connexion dans le stockage local
 */
function savePatterns() {
    try {
        localStorage.setItem('techShield_userLoginPatterns', JSON.stringify(userLoginPatterns));
        localStorage.setItem('techShield_ipLoginPatterns', JSON.stringify(ipLoginPat