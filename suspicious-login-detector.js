// Module de détection avancée des connexions suspectes pour Tech Shield

/**
 * Ce module étend les fonctionnalités de détection des connexions suspectes
 * en ajoutant des algorithmes avancés pour identifier les comportements anormaux
 * et les tentatives d'intrusion.
 */

// Configuration du détecteur de connexions suspectes
const suspiciousLoginConfig = {
    // Activer la détection des connexions suspectes
    enabled: true,
    
    // Seuils de détection pour les différents types d'anomalies
    thresholds: {
        // Connexions à des heures inhabituelles
        unusualHours: {
            enabled: true,
            startHour: 22,  // 22h00
            endHour: 6,     // 6h00
            minLoginCount: 5 // Nombre minimum de connexions pour établir un modèle
        },
        
        // Connexions depuis des emplacements inhabituels
        unusualLocations: {
            enabled: true,
            distanceThreshold: 500, // Distance en km considérée comme inhabituelle
            timeWindowHours: 24     // Fenêtre de temps pour les changements d'emplacement
        },
        
        // Connexions depuis plusieurs appareils
        multiDeviceLogin: {
            enabled: true,
            deviceCount: 3,       // Nombre d'appareils différents avant détection
            timeWindowHours: 1     // Fenêtre de temps pour les connexions
        },
        
        // Tentatives multiples de connexion échouées
        failedAttempts: {
            enabled: true,
            threshold: 5,           // Nombre de tentatives échouées avant détection
            timeWindowMinutes: 15,  // Fenêtre de temps pour les tentatives
            progressiveBlocking: true // Blocage progressif activé
        },
        
        // Détection de force brute
        bruteForce: {
            enabled: true,
            attemptsPerMinute: 10,  // Tentatives par minute considérées comme force brute
            blockDuration: 60       // Durée du blocage en minutes
        },
        
        // Détection de changement de comportement
        behaviorChange: {
            enabled: true,
            sensitivityLevel: 2,    // Niveau de sensibilité (1-3)
            learningPeriodDays: 14  // Période d'apprentissage en jours
        },
        
        // Détection de connexions simultanées
        simultaneousLogins: {
            enabled: true,
            timeWindowMinutes: 5,   // Fenêtre de temps pour considérer des connexions comme simultanées
            differentLocations: true // Considérer uniquement les connexions depuis des emplacements différents
        }
    },
    
    // Configuration des alertes
    alerts: {
        // Niveaux de sévérité
        severityLevels: {
            LOW: 'low',
            MEDIUM: 'medium',
            HIGH: 'high',
            CRITICAL: 'critical'
        },
        
        // Canaux de notification
        notificationChannels: {
            console: true,    // Afficher dans la console
            securityLogs: true, // Enregistrer dans les logs de sécurité
            elkStack: true,   // Envoyer vers ELK Stack si disponible
            dashboard: true   // Afficher sur le tableau de bord d'administration
        },
        
        // Délai minimum entre deux alertes similaires (en minutes)
        throttleMinutes: 15
    },
    
    // Configuration de l'apprentissage automatique
    machineLearning: {
        enabled: true,
        adaptiveThresholds: true, // Ajuster automatiquement les seuils en fonction des données
        minimumDataPoints: 20,    // Nombre minimum de points de données pour l'apprentissage
        anomalyDetectionSensitivity: 0.8 // Sensibilité de détection des anomalies (0-1)
    }
};

// Stockage des modèles de comportement utilisateur
let userBehaviorModels = {};

// Stockage des alertes récentes pour éviter les doublons
let recentAlerts = [];

// Compteurs pour les statistiques
let detectionStats = {
    totalDetections: 0,
    byType: {},
    falsePositives: 0
};

/**
 * Initialise le module de détection des connexions suspectes
 */
function init() {
    console.log('Initialisation du module de détection des connexions suspectes');
    
    // Charger les modèles de comportement depuis le stockage local
    loadBehaviorModels();
    
    // S'abonner aux événements de connexion si les modules nécessaires sont disponibles
    if (window.securityLogs) {
        window.securityLogs.subscribeToLoginEvents(analyzeLoginEvent);
        console.log('Abonnement aux événements de connexion réussi');
    } else {
        console.error('Module de logs de sécurité non disponible, impossible d\'initialiser la détection des connexions suspectes');
        return false;
    }
    
    // Nettoyer les alertes anciennes périodiquement
    setInterval(cleanupOldAlerts, 60 * 60 * 1000); // Toutes les heures
    
    return true;
}

/**
 * Analyse un événement de connexion pour détecter des activités suspectes
 * @param {Object} log - Log de connexion à analyser
 */
function analyzeLoginEvent(log) {
    // Vérifier si le module est activé
    if (!suspiciousLoginConfig.enabled) return;
    
    // Ne pas analyser les logs système
    if (!log.email || log.email === 'système') return;
    
    // Mettre à jour le modèle de comportement de l'utilisateur
    updateUserBehaviorModel(log);
    
    // Exécuter les différentes détections si elles sont activées
    const detections = [];
    
    if (suspiciousLoginConfig.thresholds.unusualHours.enabled) {
        const unusualHourResult = detectUnusualLoginHours(log);
        if (unusualHourResult) detections.push(unusualHourResult);
    }
    
    if (suspiciousLoginConfig.thresholds.unusualLocations.enabled) {
        const unusualLocationResult = detectUnusualLocation(log);
        if (unusualLocationResult) detections.push(unusualLocationResult);
    }
    
    if (suspiciousLoginConfig.thresholds.multiDeviceLogin.enabled) {
        const multiDeviceResult = detectMultiDeviceLogin(log);
        if (multiDeviceResult) detections.push(multiDeviceResult);
    }
    
    if (suspiciousLoginConfig.thresholds.failedAttempts.enabled && log.status === 'failure') {
        const failedAttemptsResult = detectMultipleFailedAttempts(log);
        if (failedAttemptsResult) detections.push(failedAttemptsResult);
    }
    
    if (suspiciousLoginConfig.thresholds.bruteForce.enabled && log.status === 'failure') {
        const bruteForceResult = detectBruteForceAttempt(log);
        if (bruteForceResult) detections.push(bruteForceResult);
    }
    
    if (suspiciousLoginConfig.thresholds.behaviorChange.enabled) {
        const behaviorChangeResult = detectBehaviorChange(log);
        if (behaviorChangeResult) detections.push(behaviorChangeResult);
    }
    
    if (suspiciousLoginConfig.thresholds.simultaneousLogins.enabled && log.status === 'success') {
        const simultaneousLoginResult = detectSimultaneousLogins(log);
        if (simultaneousLoginResult) detections.push(simultaneousLoginResult);
    }
    
    // Traiter les détections
    if (detections.length > 0) {
        processDetections(log, detections);
    }
    
    // Sauvegarder les modèles de comportement mis à jour
    saveBehaviorModels();
}

/**
 * Met à jour le modèle de comportement d'un utilisateur
 * @param {Object} log - Log de connexion
 */
function updateUserBehaviorModel(log) {
    const email = log.email;
    const timestamp = new Date(log.timestamp);
    const hour = timestamp.getHours();
    const day = timestamp.getDay();
    const userAgent = log.userAgent;
    const ipAddress = log.ipAddress;
    
    // Initialiser le modèle utilisateur s'il n'existe pas
    if (!userBehaviorModels[email]) {
        userBehaviorModels[email] = {
            loginTimes: [],          // Heures de connexion
            loginDays: {},           // Jours de connexion (0-6, dimanche-samedi)
            devices: {},             // Appareils utilisés
            ips: {},                 // IPs utilisées
            locations: [],           // Emplacements de connexion
            lastLogin: null,         // Dernière connexion
            failedAttempts: [],      // Tentatives échouées
            successfulLogins: [],    // Connexions réussies
            createdAt: timestamp.toISOString() // Date de création du modèle
        };
    }
    
    const model = userBehaviorModels[email];
    
    // Ajouter l'heure de connexion
    model.loginTimes.push({
        timestamp: timestamp.toISOString(),
        hour: hour,
        day: day,
        status: log.status
    });
    
    // Limiter à 100 entrées
    if (model.loginTimes.length > 100) {
        model.loginTimes.shift();
    }
    
    // Mettre à jour les statistiques de jour de connexion
    model.loginDays[day] = (model.loginDays[day] || 0) + 1;
    
    // Mettre à jour les appareils
    if (!model.devices[userAgent]) {
        model.devices[userAgent] = {
            firstSeen: timestamp.toISOString(),
            lastSeen: timestamp.toISOString(),
            count: 1
        };
    } else {
        model.devices[userAgent].lastSeen = timestamp.toISOString();
        model.devices[userAgent].count++;
    }
    
    // Mettre à jour les IPs
    if (!model.ips[ipAddress]) {
        model.ips[ipAddress] = {
            firstSeen: timestamp.toISOString(),
            lastSeen: timestamp.toISOString(),
            count: 1
        };
    } else {
        model.ips[ipAddress].lastSeen = timestamp.toISOString();
        model.ips[ipAddress].count++;
    }
    
    // Ajouter la tentative selon son statut
    if (log.status === 'failure') {
        model.failedAttempts.push({
            timestamp: timestamp.toISOString(),
            ipAddress: ipAddress,
            userAgent: userAgent
        });
        
        // Limiter à 50 entrées
        if (model.failedAttempts.length > 50) {
            model.failedAttempts.shift();
        }
    } else if (log.status === 'success') {
        model.successfulLogins.push({
            timestamp: timestamp.toISOString(),
            ipAddress: ipAddress,
            userAgent: userAgent
        });
        
        // Limiter à 50 entrées
        if (model.successfulLogins.length > 50) {
            model.successfulLogins.shift();
        }
    }
    
    // Mettre à jour la dernière connexion
    model.lastLogin = {
        timestamp: timestamp.toISOString(),
        ipAddress: ipAddress,
        userAgent: userAgent,
        status: log.status
    };
}

/**
 * Détecte les connexions à des heures inhabituelles
 * @param {Object} log - Log de connexion
 * @returns {Object|null} Résultat de la détection ou null si aucune anomalie
 */
function detectUnusualLoginHours(log) {
    const email = log.email;
    const timestamp = new Date(log.timestamp);
    const hour = timestamp.getHours();
    const config = suspiciousLoginConfig.thresholds.unusualHours;
    
    // Vérifier si l'heure est dans la plage considérée comme inhabituelle
    const isUnusualHour = (hour >= config.startHour || hour < config.endHour);
    
    if (!isUnusualHour) return null;
    
    // Vérifier si l'utilisateur a suffisamment de connexions pour établir un modèle
    const model = userBehaviorModels[email];
    if (!model || model.loginTimes.length < config.minLoginCount) return null;
    
    // Calculer les heures habituelles de connexion
    const loginHours = model.loginTimes.map(login => login.hour);
    const hourCounts = {};
    
    loginHours.forEach(h => {
        hourCounts[h] = (hourCounts[h] || 0) + 1;
    });
    
    // Calculer le pourcentage de connexions à cette heure
    const currentHourCount = hourCounts[hour] || 0;
    const hourPercentage = (currentHourCount / loginHours.length) * 100;
    
    // Si moins de 10% des connexions sont à cette heure, c'est inhabituel
    if (hourPercentage < 10) {
        return {
            type: 'unusual_login_hour',
            severity: hourPercentage < 5 ? 'medium' : 'low',
            details: `Connexion à une heure inhabituelle (${hour}h00) pour l'utilisateur ${email}`,
            data: {
                hour: hour,
                hourPercentage: hourPercentage.toFixed(2),
                userAgent: log.userAgent,
                threshold: 10
            }
        };
    }
    
    return null;
}

/**
 * Détecte les connexions depuis des emplacements inhabituels
 * @param {Object} log - Log de connexion
 * @returns {Object|null} Résultat de la détection ou null si aucune anomalie
 */
function detectUnusualLocation(log) {
    const email = log.email;
    const ipAddress = log.ipAddress;
    const timestamp = new Date(log.timestamp);
    const config = suspiciousLoginConfig.thresholds.unusualLocations;
    
    // Vérifier si l'utilisateur a une connexion précédente
    const model = userBehaviorModels[email];
    if (!model || !model.lastLogin || model.lastLogin.ipAddress === ipAddress) return null;
    
    const lastLogin = model.lastLogin;
    const lastLoginTime = new Date(lastLogin.timestamp);
    const lastIp = lastLogin.ipAddress;
    
    // Ne vérifier que si l'IP est différente et que la connexion précédente est récente
    if (lastIp !== ipAddress && 
        (timestamp - lastLoginTime) <= (config.timeWindowHours * 60 * 60 * 1000)) {
        
        // Dans un environnement réel, on utiliserait un service de géolocalisation
        // Pour cette démonstration, on simule un changement d'emplacement
        const simulatedDistance = Math.random() * 1000; // Distance simulée en km
        
        if (simulatedDistance >= config.distanceThreshold) {
            return {
                type: 'unusual_location',
                severity: simulatedDistance > config.distanceThreshold * 2 ? 'high' : 'medium',
                details: `Changement d'emplacement inhabituel pour ${email} (${lastIp} → ${ipAddress})`,
                data: {
                    previousIp: lastIp,
                    currentIp: ipAddress,
                    timeDifference: Math.round((timestamp - lastLoginTime) / (60 * 1000)), // en minutes
                    simulatedDistance: Math.round(simulatedDistance),
                    threshold: config.distanceThreshold
                }
            };
        }
    }
    
    return null;
}

/**
 * Détecte les connexions depuis plusieurs appareils dans un court laps de temps
 * @param {Object} log - Log de connexion
 * @returns {Object|null} Résultat de la détection ou null si aucune anomalie
 */
function detectMultiDeviceLogin(log) {
    const email = log.email;
    const userAgent = log.userAgent;
    const timestamp = new Date(log.timestamp);
    const config = suspiciousLoginConfig.thresholds.multiDeviceLogin;
    
    // Vérifier si l'utilisateur a des connexions précédentes
    const model = userBehaviorModels[email];
    if (!model || model.successfulLogins.length < 2) return null;
    
    // Récupérer les connexions récentes réussies
    const recentLogins = model.successfulLogins.filter(login => {
        const loginTime = new Date(login.timestamp);
        return (timestamp - loginTime) <= (config.timeWindowHours * 60 * 60 * 1000);
    });
    
    // Compter les appareils uniques dans la fenêtre de temps
    const uniqueDevices = new Set();
    recentLogins.forEach(login => {
        uniqueDevices.add(login.userAgent);
    });
    
    // Ajouter l'appareil actuel s'il n'est pas déjà compté
    uniqueDevices.add(userAgent);
    
    if (uniqueDevices.size >= config.deviceCount) {
        return {
            type: 'multi_device_login',
            severity: uniqueDevices.size > config.deviceCount + 1 ? 'high' : 'medium',
            details: `Connexions depuis ${uniqueDevices.size} appareils différents en ${config.timeWindowHours}h pour ${email}`,
            data: {
                deviceCount: uniqueDevices.size,
                timeWindow: config.timeWindowHours,
                threshold: config.deviceCount
            }
        };
    }
    
    return null;
}

/**
 * Détecte les tentatives multiples de connexion échouées
 * @param {Object} log - Log de connexion
 * @returns {Object|null} Résultat de la détection ou null si aucune anomalie
 */
function detectMultipleFailedAttempts(log) {
    const email = log.email;
    const ipAddress = log.ipAddress;
    const timestamp = new Date(log.timestamp);
    const config = suspiciousLoginConfig.thresholds.failedAttempts;
    
    // Vérifier si l'utilisateur a des tentatives échouées précédentes
    const model = userBehaviorModels[email];
    if (!model) return null;
    
    // Récupérer les tentatives échouées récentes
    const recentFailures = model.failedAttempts.filter(attempt => {
        const attemptTime = new Date(attempt.timestamp);
        return (timestamp - attemptTime) <= (config.timeWindowMinutes * 60 * 1000);
    });
    
    if (recentFailures.length >= config.threshold) {
        // Calculer la sévérité en fonction du nombre de tentatives
        let severity = 'medium';
        if (recentFailures.length >= config.threshold * 2) {
            severity = 'critical';
        } else if (recentFailures.length >= config.threshold * 1.5) {
            severity = 'high';
        }
        
        return {
            type: 'multiple_failed_attempts',
            severity: severity,
            details: `${recentFailures.length} tentatives de connexion échouées en ${config.timeWindowMinutes} minutes pour ${email}`,
            data: {
                attemptCount: recentFailures.length,
                timeWindow: config.timeWindowMinutes,
                threshold: config.threshold,
                ipAddress: ipAddress,
                progressiveBlocking: config.progressiveBlocking
            }
        };
    }
    
    return null;
}

/**
 * Détecte les tentatives de force brute
 * @param {Object} log - Log de connexion
 * @returns {Object|null} Résultat de la détection ou null si aucune anomalie
 */
function detectBruteForceAttempt(log) {
    const email = log.email;
    const ipAddress = log.ipAddress;
    const timestamp = new Date(log.timestamp);
    const config = suspiciousLoginConfig.thresholds.bruteForce;
    
    // Vérifier si l'utilisateur a des tentatives échouées précédentes
    const model = userBehaviorModels[email];
    if (!model || model.failedAttempts.length < config.attemptsPerMinute) return null;
    
    // Récupérer les tentatives échouées de la dernière minute
    const lastMinuteFailures = model.failedAttempts.filter(attempt => {
        const attemptTime = new Date(attempt.timestamp);
        return (timestamp - attemptTime) <= (60 * 1000); // 1 minute
    });
    
    if (lastMinuteFailures.length >= config.attemptsPerMinute) {
        return {
            type: 'brute_force_attempt',
            severity: 'critical',
            details: `Tentative de force brute détectée pour ${email} (${lastMinuteFailures.length} tentatives/minute)`,
            data: {
                attemptCount: lastMinuteFailures.length,
                timeWindow: 1, // 1 minute
                threshold: config.attemptsPerMinute,
                ipAddress: ipAddress,
                blockDuration: config.blockDuration
            }
        };
    }
    
    return null;
}

/**
 * Détecte les changements de comportement
 * @param {Object} log - Log de connexion
 * @returns {Object|null} Résultat de la détection ou null si aucune anomalie
 */
function detectBehaviorChange(log) {
    const email = log.email;
    const timestamp = new Date(log.timestamp);
    const config = suspiciousLoginConfig.thresholds.behaviorChange;
    
    // Vérifier si l'utilisateur a suffisamment de données pour établir un modèle
    const model = userBehaviorModels[email];
    if (!model || model.loginTimes.length < suspiciousLoginConfig.machineLearning.minimumDataPoints) return null;
    
    // Vérifier si le modèle est suffisamment ancien pour être fiable
    const modelCreationDate = new Date(model.createdAt);
    const modelAgeDays = (timestamp - modelCreationDate) / (24 * 60 * 60 * 1000);
    if (modelAgeDays < config.learningPeriodDays) return null;
    
    // Calculer un score d'anomalie basé sur plusieurs facteurs
    let anomalyScore = 0;
    
    // 1. Vérifier si l'heure de connexion est inhabituelle
    const hour = timestamp.getHours();
    const loginHours = model.loginTimes.map(login => login.hour);
    const hourCounts = {};
    loginHours.forEach(h => { hourCounts[h] = (hourCounts[h] || 0) + 1; });
    const hourFrequency = (hourCounts[hour] || 0) / loginHours.length;
    if (hourFrequency < 0.1) anomalyScore += 0.3;
    
    // 2. Vérifier si le jour de connexion est inhabituel
    const day = timestamp.getDay();
    const dayFrequency = (model.loginDays[day] || 0) / model.loginTimes.length;
    if (dayFrequency < 0.1) anomalyScore += 0.2;
    
    // 3. Vérifier si l'appareil est nouveau ou rarement utilisé
    const userAgent = log.userAgent;
    const deviceUsage = model.devices[userAgent];
    if (!deviceUsage) {
        anomalyScore += 0.3;
    } else if (deviceUsage.count < 3) {
        anomalyScore += 0.2;
    }
    
    // 4. Vérifier si l'IP est nouvelle ou rarement utilisée
    const ipAddress = log.ipAddress;
    const ipUsage = model.ips[ipAddress];
    if (!ipUsage) {
        anomalyScore += 0.3;
    } else if (ipUsage.count < 3) {
        anomalyScore += 0.2;
    }
    
    // Ajuster le score en fonction du niveau de sensibilité
    const sensitivityMultiplier = config.sensitivityLevel / 2;
    anomalyScore *= sensitivityMultiplier;
    
    // Si le score dépasse le seuil, signaler un changement de comportement
    if (anomalyScore >= suspiciousLoginConfig.machineLearning.anomalyDetectionSensitivity) {
        // Déterminer la sévérité en fonction du score
        let severity = 'low';
        if (anomalyScore > 0.9) {
            severity = 'high';
        } else if (anomalyScore > 0.7) {
            severity = 'medium';
        }
        
        return {
            type: 'behavior_change',
            severity: severity,
            details: `Changement de comportement détecté pour ${email} (score: ${(anomalyScore * 100).toFixed(0)}%)`,
            data: {
                anomalyScore: anomalyScore.toFixed(2),
                hourFrequency: hourFrequency.toFixed(2),
                dayFrequency: dayFrequency.toFixed(2),
                deviceFamiliarity: deviceUsage ? deviceUsage.count : 0,
                ipFamiliarity: ipUsage ? ipUsage.count : 0,
                sensitivityLevel: config.sensitivityLevel
            }
        };
    }
    
    return null;
}

/**
 * Détecte les connexions simultanées
 * @param {Object} log - Log de connexion
 * @returns {Object|null} Résultat de la détection ou null si aucune anomalie
 */
function detectSimultaneousLogins(log) {
    const email = log.email;
    const ipAddress = log.ipAddress;
    const timestamp = new Date(log.timestamp);
    const config = suspiciousLoginConfig.thresholds.simultaneousLogins;
    
    // Vérifier si l'utilisateur a des connexions réussies précédentes
    const model = userBehaviorModels[email];
    if (!model || model.successfulLogins.length === 0) return null;
    
    // Récupérer les connexions réussies récentes
    const recentLogins = model.successfulLogins.filter(login => {
        const loginTime = new Date(login.timestamp);
        const timeDiff = Math.abs(timestamp - loginTime);
        return timeDiff <= (config.timeWindowMinutes * 60 * 1000);
    });
    
    // Vérifier s'il y a des connexions depuis des IPs différentes
    if (recentLogins.length > 0) {
        const differentLocationLogins = recentLogins.filter(login => 
            login.ipAddress !== ipAddress
        );
        
        if (differentLocationLogins.length > 0 && config.differentLocations) {
            return {
                type: 'simultaneous_logins',
                severity: 'high',
                details: `Connexions simultanées détectées pour ${email} depuis des emplacements différents`,
                data: {
                    currentIp: ipAddress,
                    otherIps: differentLocationLogins.map(l => l.ipAddress),
                    timeWindow: config.timeWindowMinutes
                }
            };
        } else if (recentLogins.length > 1 && !config.differentLocations) {
            return {
                type: 'simultaneous_logins',
                severity: 'medium',
                details: `Connexions simultanées détectées pour ${email}`,
                data: {
                    currentIp: ipAddress,
                    loginCount: recentLogins.length + 1,
                    timeWindow: config.timeWindowMinutes
                }
            };
        }
    }
    
    return null;
}

/**
 * Traite les détections et génère des alertes
 * @param {Object} log - Log de connexion original
 * @param {Array} detections - Liste des détections
 */
function processDetections(log, detections) {
    // Mettre à jour les statistiques
    detectionStats.totalDetections += detections.length;
    
    // Traiter chaque détection
    detections.forEach(detection => {
        // Mettre à jour les statistiques par type
        detectionStats.byType[detection.type] = (detectionStats.byType[detection.type] || 0) + 1;
        
        // Vérifier si une alerte similaire a été générée récemment
        if (isAlertThrottled(detection, log.email)) {
            console.log(`Alerte throttled: ${detection.type} pour ${log.email}`);
            return;
        }
        
        // Enregistrer l'alerte comme récente
        addRecentAlert(detection, log.email);
        
        // Notifier via les différents canaux configurés
        notifyDetection(detection, log);
        
        // Prendre des mesures automatiques selon le type et la sévérité
        takeAutomatedActions(detection, log);
    });
}

/**
 * Vérifie si une alerte similaire a été générée récemment
 * @param {Object} detection - Détection à vérifier
 * @param {string} email - Email de l'utilisateur
 * @returns {boolean} True si l'alerte doit être throttled
 */
function isAlertThrottled(detection, email) {
    const now = new Date();
    const throttleWindow = suspiciousLoginConfig.alerts.throttleMinutes * 60 * 1000;
    
    // Rechercher une alerte similaire récente
    const similarAlert = recentAlerts.find(alert => {
        return alert.type === detection.type && 
               alert.email === email && 
               (now - new Date(alert.timestamp)) < throttleWindow;
    });
    
    return !!similarAlert;
}

/**
 * Ajoute une alerte à la liste des alertes récentes
 * @param {Object} detection - Détection à ajouter
 * @param {string} email - Email de l'utilisateur
 */
function addRecentAlert(detection, email) {
    recentAlerts.push({
        type: detection.type,
        email: email,
        severity: detection.severity,
        timestamp: new Date().toISOString()
    });
    
    // Limiter la taille de la liste
    if (recentAlerts.length > 100) {
        recentAlerts.shift();
    }
}

/**
 * Nettoie les alertes anciennes
 */
function cleanupOldAlerts() {
    const now = new Date();
    const maxAge = 24 * 60 * 60 * 1000; // 24 heures
    
    recentAlerts = recentAlerts.filter(alert => {
        return (now - new Date(alert.timestamp)) < maxAge;
    });
}

/**
 * Notifie une détection via les différents canaux configurés
 * @param {Object} detection - Détection à notifier
 * @param {Object} log - Log de connexion original
 */
function notifyDetection(detection, log) {
    const channels = suspiciousLoginConfig.alerts.notificationChannels;
    
    // Notification console
    if (channels.console) {
        console.log(`[DÉTECTION] ${detection.severity.toUpperCase()}: ${detection.details}`);
        console.log(detection.data);
    }
    
    // Notification dans les logs de sécurité
    if (channels.securityLogs && window.securityLogs) {
        // Convertir la sévérité en type de log
        let logType;
        switch (detection.severity) {
            case 'critical':
                logType = window.securityLogs.LOG_TYPES.CRITICAL;
                break;
            case 'high':
                logType = window.securityLogs.LOG_TYPES.SUSPICIOUS;
                break;
            case 'medium':
                logType = window.securityLogs.LOG_TYPES.WARNING;
                break;
            default:
                logType = window.securityLogs.LOG_TYPES.INFO;
        }
        
        // Ajouter un log
        window.securityLogs.addLoginLog(
            log.email,
            log.ipAddress,
            logType,
            detection.details,
            {
                detectionType: detection.type,
                detectionData: detection.data
            }
        );
        
        // Créer une alerte pour les détections de sévérité élevée
        if (detection.severity === 'high' || detection.severity === 'critical') {
            window.securityLogs.createSecurityAlert(
                `Activité suspecte: ${detection.type}`,
                detection.details,
                logType,
                {
                    email: log.email,
                    ipAddress: log.ipAddress,
                    detectionType: detection.type,
                    detectionData: detection.data
                }
            );
        }
    }
    
    // Notification vers ELK Stack
    if (channels.elkStack && window.elkIntegration) {
        // L'intégration ELK est gérée via l'abonnement aux événements de logs
        // Aucune action supplémentaire n'est nécessaire ici
    }
}

/**
 * Prend des mesures automatiques en fonction de la détection
 * @param {Object} detection - Détection à traiter
 * @param {Object} log - Log de connexion original
 */
function takeAutomatedActions(detection, log) {
    const ipAddress = log.ipAddress;
    const email = log.email;
    
    // Actions selon le type de détection
    switch (detection.type) {
        case 'brute_force_attempt':
            // Bloquer l'IP en cas de force brute
            if (window.securityLogs && window.securityLogs.blockIP) {
                const blockDuration = detection.data.blockDuration || 60;
                window.securityLogs.blockIP(ipAddress, `Tentative de force brute détectée`, blockDuration);
                console.log(`IP ${ipAddress} bloquée pour ${blockDuration} minutes suite à une tentative de force brute`);
            }
            break;
            
        case 'multiple_failed_attempts':
            // Bloquer progressivement l'IP en cas de tentatives multiples
            if (detection.data.progressiveBlocking && window.securityLogs && window.securityLogs.blockIP) {
                // Calculer la durée du blocage en fonction du nombre de tentatives
                const attemptCount = detection.data.attemptCount;
                const baseDuration = 15; // 15 minutes de base
                const blockDuration = Math.min(baseDuration * Math.pow(1.5, attemptCount - 5), 120); // Max 2 heures
                
                window.securityLogs.blockIP(ipAddress, `Trop de tentatives échouées`, Math.round(blockDuration));
                console.log(`IP ${ipAddress} bloquée pour ${Math.round(blockDuration)} minutes suite à ${attemptCount} tentatives échouées`);
            }
            break;
            
        case 'simultaneous_logins':
            // Forcer la déconnexion des autres sessions en cas de connexions simultanées
            if (detection.severity === 'high' && window.auth && window.auth.invalidateOtherSessions) {
                window.auth.invalidateOtherSessions(email, ipAddress);
                console.log(`Sessions invalidées pour ${email} sauf celle depuis ${ipAddress}`);
            }
            break;
            
        case 'unusual_location':
            // Demander une vérification supplémentaire en cas d'emplacement inhabituel
            if (detection.severity === 'high' && window.auth && window.auth.requireAdditionalVerification) {
                window.auth.requireAdditionalVerification(email, 'location');
                console.log(`Vérification supplémentaire requise pour ${email} en raison d'un emplacement inhabituel`);
            }
            break;
    }
}

/**
 * Charge les modèles de comportement depuis le stockage local
 */
function loadBehaviorModels() {
    try {
        const storedModels = localStorage.getItem('techShield_behaviorModels');
        if (storedModels) {
            userBehaviorModels = JSON.parse(storedModels);
            console.log(`Modèles de comportement chargés pour ${Object.keys(userBehaviorModels).length} utilisateurs`);
        }
    } catch (error) {
        console.error('Erreur lors du chargement des modèles de comportement:', error);
    }
}

/**
 * Sauvegarde les modèles de comportement dans le stockage local
 */
function saveBehaviorModels() {
    try {
        localStorage.setItem('techShield_behaviorModels', JSON.stringify(userBehaviorModels));
    } catch (error) {
        console.error('Erreur lors de la sauvegarde des modèles de comportement:', error);
        
        // Si l'erreur est due à la taille du stockage, purger les anciens modèles
        if (error.name === 'QuotaExceededError') {
            purgeBehaviorModels();
            try {
                localStorage.setItem('techShield_behaviorModels', JSON.stringify(userBehaviorModels));
            } catch (e) {
                console.error('Impossible de sauvegarder les modèles même après purge:', e);
            }
        }
    }
}

/**
 * Purge les modèles de comportement anciens ou peu utilisés
 */
function purgeBehaviorModels() {
    const now = new Date();
    const maxAge = 90 * 24 * 60 * 60 * 1000; // 90 jours
    
    // Filtrer les modèles trop anciens
    Object.keys(userBehaviorModels).forEach(email => {
        const model = userBehaviorModels[email];
        const lastActivity = model.lastLogin ? new Date(model.lastLogin.timestamp) : new Date(0);
        
        if ((now - lastActivity) > maxAge) {
            delete userBehaviorModels[email];
        }
    });
    
    console.log(`Purge des modèles de comportement effectuée, ${Object.keys(userBehaviorModels).length} modèles conservés`);
}

/**
 * Obtient les statistiques de détection
 * @returns {Object} Statistiques de détection
 */
function getDetectionStats() {
    return { ...detectionStats };
}

/**
 * Réinitialise les statistiques de détection
 */
function resetDetectionStats() {
    detectionStats = {
        totalDetections: 0,
        byType: {},
        falsePositives: 0
    };
}

/**
 * Marque une détection comme faux positif
 * @param {string} detectionId - ID de la détection
 * @param {string} reason - Raison du faux positif
 */
function markAsFalsePositive(detectionId, reason) {
    // Incrémenter le compteur de faux positifs
    detectionStats.falsePositives++;
    
    // Dans un système réel, on enregistrerait cette information pour améliorer les algorithmes
    console.log(`Détection ${detectionId} marquée comme faux positif: ${reason}`);
    
    // Si l'apprentissage automatique est activé, ajuster les seuils
    if (suspiciousLoginConfig.machineLearning.adaptiveThresholds) {
        // Logique d'ajustement des seuils (simplifiée pour la démonstration)
        console.log('Ajustement des seuils de détection suite à un faux positif');
    }
}

// Exposer les fonctions publiques
window.suspiciousLoginDetector = {
    init,
    getConfig: () => ({ ...suspiciousLoginConfig }),
    setConfig: (newConfig) => {
        Object.assign(suspiciousLoginConfig, newConfig);
    },
    getDetectionStats,
    resetDetectionStats,
    markAsFalsePositive,
    getUserBehaviorModel: (email) => userBehaviorModels[email] ? { ...userBehaviorModels[email] } : null
};

// Initialiser automatiquement si le document est déjà chargé
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(init, 1000);
} else {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 1000));
}