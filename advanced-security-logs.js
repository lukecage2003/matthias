// Module avancé de journalisation et détection des connexions suspectes pour Tech Shield

// Configuration de la détection des comportements suspects
const suspiciousActivityConfig = {
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
    },
    
    // Règles de détection avancées
    detectionRules: [
        {
            name: 'failed_login_attempts',
            description: 'Tentatives de connexion échouées multiples',
            check: function(logs, userEmail) {
                const recentLogs = filterRecentLogs(logs, 1); // Dernière heure
                const failedLogins = recentLogs.filter(log => 
                    log.email === userEmail && 
                    log.status === window.securityLogs.LOG_TYPES.FAILURE
                );
                
                return {
                    detected: failedLogins.length >= suspiciousActivityConfig.thresholds.failedLoginAttempts,
                    count: failedLogins.length,
                    severity: failedLogins.length >= 5 ? 
                        suspiciousActivityConfig.severityLevels.HIGH : 
                        suspiciousActivityConfig.severityLevels.MEDIUM,
                    details: `${failedLogins.length} tentatives de connexion échouées dans la dernière heure`
                };
            }
        },
        {
            name: 'geo_location_change',
            description: 'Connexions depuis des emplacements géographiques différents',
            check: function(logs, userEmail) {
                // Dans un environnement réel, cette fonction utiliserait un service de géolocalisation IP
                // Pour cette démonstration, nous simulons la détection
                return {
                    detected: false,
                    severity: suspiciousActivityConfig.severityLevels.HIGH,
                    details: 'Fonctionnalité de détection géographique non implémentée dans cette démo'
                };
            }
        },
        {
            name: 'odd_hour_login',
            description: 'Connexions à des heures inhabituelles',
            check: function(logs, userEmail) {
                const recentLogs = filterRecentLogs(logs, 48); // 48 dernières heures
                const oddHourLogins = recentLogs.filter(log => {
                    if (log.email !== userEmail || log.status !== window.securityLogs.LOG_TYPES.SUCCESS) {
                        return false;
                    }
                    
                    const logTime = new Date(log.timestamp);
                    const hour = logTime.getHours();
                    
                    // Vérifier si l'heure est en dehors des heures de bureau
                    return hour < suspiciousActivityConfig.thresholds.oddHourLogins.workHoursStart || 
                           hour > suspiciousActivityConfig.thresholds.oddHourLogins.workHoursEnd;
                });
                
                return {
                    detected: oddHourLogins.length >= suspiciousActivityConfig.thresholds.oddHourLogins.count,
                    count: oddHourLogins.length,
                    severity: suspiciousActivityConfig.severityLevels.LOW,
                    details: `${oddHourLogins.length} connexions en dehors des heures de bureau`
                };
            }
        },
        {
            name: 'brute_force_attack',
            description: 'Tentative d\'attaque par force brute',
            check: function(logs, userEmail) {
                const recentLogs = filterRecentLogs(logs, 0.5); // 30 dernières minutes
                
                // Regrouper les tentatives par adresse IP
                const attemptsByIP = {};
                
                recentLogs.forEach(log => {
                    if (log.status === window.securityLogs.LOG_TYPES.FAILURE) {
                        if (!attemptsByIP[log.ipAddress]) {
                            attemptsByIP[log.ipAddress] = 0;
                        }
                        attemptsByIP[log.ipAddress]++;
                    }
                });
                
                // Vérifier s'il y a une IP avec beaucoup de tentatives
                let maxAttempts = 0;
                let suspiciousIP = null;
                
                for (const ip in attemptsByIP) {
                    if (attemptsByIP[ip] > maxAttempts) {
                        maxAttempts = attemptsByIP[ip];
                        suspiciousIP = ip;
                    }
                }
                
                const isBruteForce = maxAttempts >= 10; // Seuil arbitraire pour la démonstration
                
                return {
                    detected: isBruteForce,
                    count: maxAttempts,
                    ipAddress: suspiciousIP,
                    severity: isBruteForce ? suspiciousActivityConfig.severityLevels.CRITICAL : suspiciousActivityConfig.severityLevels.LOW,
                    details: isBruteForce ? 
                        `Possible attaque par force brute depuis l'IP ${suspiciousIP} (${maxAttempts} tentatives)` : 
                        'Aucune attaque par force brute détectée'
                };
            }
        }
    ]
};

// Fonction pour filtrer les logs récents
function filterRecentLogs(logs, hoursAgo) {
    const cutoffTime = new Date();
    cutoffTime.setHours(cutoffTime.getHours() - hoursAgo);
    
    return logs.filter(log => new Date(log.timestamp) >= cutoffTime);
}

// Fonction pour analyser les logs et détecter les activités suspectes
function detectSuspiciousActivity(userEmail) {
    // Vérifier si le module de logs est disponible
    if (!window.securityLogs) {
        console.error('Le module de journalisation de sécurité n\'est pas disponible');
        return [];
    }
    
    // Obtenir tous les logs
    const logs = window.securityLogs.getAllLogs();
    
    // Appliquer toutes les règles de détection
    const detectionResults = [];
    
    suspiciousActivityConfig.detectionRules.forEach(rule => {
        const result = rule.check(logs, userEmail);
        
        if (result.detected) {
            detectionResults.push({
                rule: rule.name,
                description: rule.description,
                severity: result.severity,
                details: result.details,
                timestamp: new Date().toISOString()
            });
        }
    });
    
    return detectionResults;
}

// Fonction pour générer un rapport de sécurité pour un utilisateur
function generateSecurityReport(userEmail) {
    // Vérifier si le module de logs est disponible
    if (!window.securityLogs) {
        return {
            error: 'Le module de journalisation de sécurité n\'est pas disponible'
        };
    }
    
    // Obtenir les logs de l'utilisateur
    const userLogs = window.securityLogs.getLogsByUser(userEmail);
    
    // Calculer des statistiques
    const successfulLogins = userLogs.filter(log => log.status === window.securityLogs.LOG_TYPES.SUCCESS).length;
    const failedLogins = userLogs.filter(log => log.status === window.securityLogs.LOG_TYPES.FAILURE).length;
    
    // Obtenir la dernière connexion réussie
    const lastSuccessfulLogin = userLogs
        .filter(log => log.status === window.securityLogs.LOG_TYPES.SUCCESS)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
    
    // Détecter les activités suspectes
    const suspiciousActivities = detectSuspiciousActivity(userEmail);
    
    // Générer le rapport
    return {
        userEmail: userEmail,
        reportDate: new Date().toISOString(),
        statistics: {
            totalLogins: userLogs.length,
            successfulLogins: successfulLogins,
            failedLogins: failedLogins,
            successRate: userLogs.length > 0 ? (successfulLogins / userLogs.length * 100).toFixed(2) + '%' : 'N/A'
        },
        lastSuccessfulLogin: lastSuccessfulLogin ? {
            timestamp: lastSuccessfulLogin.timestamp,
            ipAddress: lastSuccessfulLogin.ipAddress
        } : null,
        suspiciousActivities: suspiciousActivities,
        riskLevel: calculateRiskLevel(suspiciousActivities)
    };
}

// Fonction pour calculer le niveau de risque global
function calculateRiskLevel(suspiciousActivities) {
    if (suspiciousActivities.length === 0) {
        return 'Faible';
    }
    
    // Vérifier s'il y a des activités critiques
    const hasCritical = suspiciousActivities.some(activity => 
        activity.severity === suspiciousActivityConfig.severityLevels.CRITICAL
    );
    
    if (hasCritical) {
        return 'Critique';
    }
    
    // Vérifier s'il y a des activités de gravité élevée
    const hasHigh = suspiciousActivities.some(activity => 
        activity.severity === suspiciousActivityConfig.severityLevels.HIGH
    );
    
    if (hasHigh) {
        return 'Élevé';
    }
    
    // Vérifier s'il y a des activités de gravité moyenne
    const hasMedium = suspiciousActivities.some(activity => 
        activity.severity === suspiciousActivityConfig.severityLevels.MEDIUM
    );
    
    if (hasMedium) {
        return 'Moyen';
    }
    
    // Sinon, le niveau de risque est faible
    return 'Faible';
}

// Fonction pour notifier l'administrateur des activités suspectes
function notifyAdmin(suspiciousActivities) {
    // Dans un environnement réel, cette fonction enverrait un email ou une notification
    // Pour cette démonstration, nous affichons simplement une alerte dans la console
    if (suspiciousActivities.length > 0) {
        console.warn('Activités suspectes détectées:', suspiciousActivities);
        
        // Ajouter une notification dans l'interface si elle existe
        const notificationContainer = document.getElementById('securityNotifications');
        if (notificationContainer) {
            // Créer un élément pour la notification
            const notification = document.createElement('div');
            notification.className = 'security-notification';
            
            // Déterminer la classe CSS en fonction de la gravité la plus élevée
            let highestSeverity = suspiciousActivityConfig.severityLevels.LOW;
            
            suspiciousActivities.forEach(activity => {
                if (activity.severity === suspiciousActivityConfig.severityLevels.CRITICAL) {
                    highestSeverity = suspiciousActivityConfig.severityLevels.CRITICAL;
                } else if (activity.severity === suspiciousActivityConfig.severityLevels.HIGH && 
                           highestSeverity !== suspiciousActivityConfig.severityLevels.CRITICAL) {
                    highestSeverity = suspiciousActivityConfig.severityLevels.HIGH;
                } else if (activity.severity === suspiciousActivityConfig.severityLevels.MEDIUM && 
                           highestSeverity !== suspiciousActivityConfig.severityLevels.CRITICAL && 
                           highestSeverity !== suspiciousActivityConfig.severityLevels.HIGH) {
                    highestSeverity = suspiciousActivityConfig.severityLevels.MEDIUM;
                }
            });
            
            notification.classList.add(`severity-${highestSeverity}`);
            
            // Construire le contenu de la notification
            notification.innerHTML = `
                <div class="notification-header">
                    <span class="notification-title">Alerte de sécurité</span>
                    <span class="notification-time">${new Date().toLocaleTimeString()}</span>
                </div>
                <div class="notification-content">
                    <p>${suspiciousActivities.length} activité(s) suspecte(s) détectée(s) :</p>
                    <ul>
                        ${suspiciousActivities.map(activity => `
                            <li>
                                <strong>${activity.description}</strong>: ${activity.details}
                                <span class="severity-badge ${activity.severity}">${activity.severity}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
                <div class="notification-actions">
                    <button class="view-details-btn">Voir les détails</button>
                    <button class="dismiss-btn">Ignorer</button>
                </div>
            `;
            
            // Ajouter la notification au conteneur
            notificationContainer.insertBefore(notification, notificationContainer.firstChild);
            
            // Ajouter des gestionnaires d'événements pour les boutons
            const viewDetailsBtn = notification.querySelector('.view-details-btn');
            const dismissBtn = notification.querySelector('.dismiss-btn');
            
            if (viewDetailsBtn) {
                viewDetailsBtn.addEventListener('click', function() {
                    // Rediriger vers la page des logs ou afficher un modal avec les détails
                    const tabLinks = document.querySelectorAll('.admin-nav a');
                    tabLinks.forEach(link => {
                        if (link.getAttribute('data-tab') === 'logs') {
                            link.click();
                        }
                    });
                });
            }
            
            if (dismissBtn) {
                dismissBtn.addEventListener('click', function() {
                    // Supprimer la notification
                    notification.remove();
                });
            }
        }
    }
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.advancedSecurityLogs = {
    detectSuspiciousActivity,
    generateSecurityReport,
    notifyAdmin,
    suspiciousActivityConfig
};