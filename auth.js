// Système d'authentification pour Tech Shield

// Stockage des utilisateurs (dans un environnement de production, cela serait géré côté serveur)
const users = {
    "admin@techshield.com": {
        password: "Admin123!",
        role: "admin",
        lastLogin: null,
        loginAttempts: 0,
        lockedUntil: null
    }
};

// Configuration des tentatives de connexion
const loginConfig = {
    maxAttempts: 5,
    lockoutTime: 15 // minutes
};

// Fonction pour vérifier les identifiants
function authenticate(email, password, twofaCode = null) {
    // Obtenir l'adresse IP du client
    const clientIP = window.ipWhitelist ? window.ipWhitelist.getClientIP() : '127.0.0.1';
    // Obtenir l'agent utilisateur (User-Agent) du navigateur
    const userAgent = navigator.userAgent || 'Unknown';
    
    // Vérifier si l'utilisateur existe
    if (users[email]) {
        // Vérifier si le compte est verrouillé
        if (users[email].lockedUntil && new Date(users[email].lockedUntil) > new Date()) {
            // Enregistrer la tentative dans les logs
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.FAILURE, 'Compte verrouillé');
            }
            return { 
                success: false, 
                locked: true, 
                lockedUntil: users[email].lockedUntil 
            };
        }
        
        // Vérifier si l'IP est bloquée temporairement (si le module loginSecurity est disponible)
        if (window.loginSecurity) {
            const blockStatus = window.loginSecurity.isIPBlocked(clientIP);
            if (blockStatus.blocked) {
                // Enregistrer la tentative dans les logs
                if (window.securityLogs) {
                    window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.FAILURE, 
                        `Tentative de connexion depuis une IP bloquée (${blockStatus.remainingMinutes} minutes restantes)`);
                }
                return { 
                    success: false, 
                    ipBlocked: true,
                    blockStatus: blockStatus
                };
            }
        }
        
        // Vérifier si l'IP est dans la liste blanche pour les comptes admin
        if (users[email].role === 'admin' && window.ipWhitelist) {
            const ipAccess = window.ipWhitelist.checkIPAccess();
            if (!ipAccess.allowed) {
                // Enregistrer la tentative dans les logs
                if (window.securityLogs) {
                    window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.SUSPICIOUS, 'Tentative d\'accès admin depuis une IP non autorisée');
                }
                
                // Enregistrer la tentative échouée si le module loginSecurity est disponible
                if (window.loginSecurity) {
                    window.loginSecurity.recordLoginAttempt(email, clientIP, userAgent, false);
                }
                
                return { success: false, ipNotAllowed: true };
            }
        }
        
        // Vérifier si le mot de passe correspond
        if (users[email].password === password) {
            // Réinitialiser le compteur de tentatives
            users[email].loginAttempts = 0;
            users[email].lockedUntil = null;
            
            // Vérifier si l'authentification à deux facteurs est requise
            if (window.twoFA && window.twoFA.isTwoFAEnabled(email)) {
                // Si le code 2FA n'est pas fourni, retourner un statut spécial
                if (!twofaCode) {
                    return { requireTwoFA: true };
                }
                
                // Vérifier le code 2FA
                if (!window.twoFA.verifyTOTP(email, twofaCode)) {
                    // Enregistrer la tentative dans les logs
                    if (window.securityLogs) {
                        window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.FAILURE, 'Code 2FA invalide');
                    }
                    
                    // Enregistrer la tentative échouée si le module loginSecurity est disponible
                    if (window.loginSecurity) {
                        window.loginSecurity.recordLoginAttempt(email, clientIP, userAgent, false);
                    }
                    
                    return { invalidTwoFA: true };
                }
            }
            
            // Vérifier si la connexion est suspecte (changement d'appareil, de localisation, etc.)
            let suspiciousLogin = false;
            if (window.loginSecurity && window.loginSecurity.isLoginSuspicious) {
                suspiciousLogin = window.loginSecurity.isLoginSuspicious(email, clientIP, userAgent);
                
                if (suspiciousLogin) {
                    // Enregistrer la connexion suspecte dans les logs
                    if (window.securityLogs) {
                        window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.SUSPICIOUS, 
                            'Connexion depuis un nouvel appareil ou une nouvelle localisation');
                    }
                }
            }
            
            // Mettre à jour la date de dernière connexion
            users[email].lastLogin = new Date().toLocaleString();
            
            // Stocker les informations de session
            sessionStorage.setItem('isLoggedIn', 'true');
            sessionStorage.setItem('userEmail', email);
            sessionStorage.setItem('userRole', users[email].role);
            sessionStorage.setItem('lastLogin', users[email].lastLogin);
            
            // Enregistrer la connexion réussie dans les logs
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.SUCCESS, 'Connexion réussie');
            }
            
            // Enregistrer la tentative réussie si le module loginSecurity est disponible
            if (window.loginSecurity) {
                window.loginSecurity.recordLoginAttempt(email, clientIP, userAgent, true);
            }
            
            // Détecter les activités suspectes si le module advancedSecurityLogs est disponible
            if (window.advancedSecurityLogs) {
                const suspiciousActivities = window.advancedSecurityLogs.detectSuspiciousActivity(email);
                if (suspiciousActivities.length > 0) {
                    window.advancedSecurityLogs.notifyAdmin(suspiciousActivities);
                }
            }
            
            return { 
                success: true,
                suspiciousLogin: suspiciousLogin
            };
        } else {
            // Incrémenter le compteur de tentatives
            users[email].loginAttempts = (users[email].loginAttempts || 0) + 1;
            
            // Enregistrer la tentative échouée si le module loginSecurity est disponible
            if (window.loginSecurity) {
                const blockStatus = window.loginSecurity.recordLoginAttempt(email, clientIP, userAgent, false);
                
                // Vérifier si l'IP doit être bloquée
                if (blockStatus && blockStatus.blocked) {
                    // Enregistrer le blocage dans les logs
                    if (window.securityLogs) {
                        window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.WARNING, 
                            `IP bloquée temporairement pour ${blockStatus.remainingMinutes} minutes suite à trop de tentatives échouées`);
                    }
                    
                    return { 
                        success: false, 
                        ipBlocked: true,
                        blockStatus: blockStatus
                    };
                }
            }
            
            // Vérifier si le compte doit être verrouillé
            if (users[email].loginAttempts >= loginConfig.maxAttempts) {
                const lockoutTime = new Date();
                lockoutTime.setMinutes(lockoutTime.getMinutes() + loginConfig.lockoutTime);
                users[email].lockedUntil = lockoutTime.toISOString();
                
                // Enregistrer le verrouillage dans les logs
                if (window.securityLogs) {
                    window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.WARNING, 'Compte verrouillé après ' + loginConfig.maxAttempts + ' tentatives échouées');
                }
                
                return { 
                    success: false, 
                    locked: true, 
                    lockedUntil: users[email].lockedUntil 
                };
            }
            
            // Enregistrer la tentative échouée dans les logs
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.FAILURE, 'Mot de passe incorrect');
            }
            
            // Vérifier si une attaque par force brute est en cours
            if (window.loginSecurity && window.loginSecurity.detectBruteForceAttack) {
                const bruteForceDetected = window.loginSecurity.detectBruteForceAttack(clientIP);
                if (bruteForceDetected) {
                    return { 
                        success: false, 
                        bruteForceDetected: true
                    };
                }
            }
        }
    } else {
        // Enregistrer la tentative avec un utilisateur inexistant
        if (window.securityLogs && email) {
            window.securityLogs.addLoginLog(email, clientIP, window.securityLogs.LOG_TYPES.FAILURE, 'Utilisateur inexistant');
        }
        
        // Enregistrer la tentative échouée si le module loginSecurity est disponible
        if (window.loginSecurity && email) {
            window.loginSecurity.recordLoginAttempt(email, clientIP, userAgent, false);
            
            // Vérifier si une attaque par force brute est en cours
            if (window.loginSecurity.detectBruteForceAttack) {
                window.loginSecurity.detectBruteForceAttack(clientIP);
            }
        }
    }
    
    return { success: false };
}

// Fonction pour vérifier si l'utilisateur est connecté
function isAuthenticated() {
    return sessionStorage.getItem('isLoggedIn') === 'true';
}

// Fonction pour déconnecter l'utilisateur
function logout() {
    sessionStorage.removeItem('isLoggedIn');
    sessionStorage.removeItem('userEmail');
    sessionStorage.removeItem('userRole');
    sessionStorage.removeItem('lastLogin');
    
    // Rediriger vers la page de connexion
    window.location.href = 'login.html';
}

// Fonction pour changer le mot de passe d'un utilisateur
function changePassword(email, newPassword) {
    if (users[email]) {
        users[email].password = newPassword;
        return true;
    }
    return false;
}

// Fonction pour ajouter un nouvel utilisateur
function addUser(email, password, role = 'user') {
    if (!users[email]) {
        users[email] = {
            password: password,
            role: role,
            lastLogin: null
        };
        return true;
    }
    return false;
}

// Fonction pour supprimer un utilisateur
function removeUser(email) {
    if (users[email]) {
        delete users[email];
        return true;
    }
    return false;
}

// Fonction pour obtenir la liste des utilisateurs (sans les mots de passe)
function getUsers() {
    const userList = {};
    for (const email in users) {
        userList[email] = {
            role: users[email].role,
            lastLogin: users[email].lastLogin
        };
    }
    return userList;
}

// Fonction pour vérifier si l'utilisateur actuel est administrateur
function isAdmin() {
    return sessionStorage.getItem('userRole') === 'admin';
}

// Fonction pour protéger les pages d'administration
function protectAdminPage() {
    // Vérifier si l'utilisateur est authentifié
    if (!isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }
    
    // Vérifier si l'utilisateur est administrateur
    if (!isAdmin()) {
        window.location.href = 'unauthorized.html';
        return;
    }
    
    // Vérifier les permissions si le module userPermissions est disponible
    if (window.userPermissions) {
        const pageName = window.location.pathname.split('/').pop() || 'index.html';
        const userRole = sessionStorage.getItem('userRole') || 'guest';
        
        if (!window.userPermissions.canAccessPage(userRole, pageName)) {
            window.location.href = 'unauthorized.html';
            return;
        }
    }
    
    // Vérifier si l'IP est autorisée
    if (window.ipWhitelist) {
        const ipAccess = window.ipWhitelist.checkIPAccess();
        if (!ipAccess.allowed) {
            // Enregistrer la tentative dans les logs
            const clientIP = window.ipWhitelist.getClientIP();
            const userEmail = sessionStorage.getItem('userEmail') || 'unknown';
            
            if (window.securityLogs) {
                window.securityLogs.addLoginLog(userEmail, clientIP, window.securityLogs.LOG_TYPES.SUSPICIOUS, 
                    'Tentative d\'accès à une page d\'administration depuis une IP non autorisée');
            }
            
            window.location.href = 'unauthorized.html';
            return;
        }
    }
}

// Fonction pour obtenir la configuration des tentatives de connexion
function getLoginConfig() {
    return { ...loginConfig };
}

// Fonction pour mettre à jour la configuration des tentatives de connexion
function updateLoginConfig(maxAttempts, lockoutTime) {
    loginConfig.maxAttempts = maxAttempts;
    loginConfig.lockoutTime = lockoutTime;
    return true;
}

// Exporter les fonctions pour les utiliser dans d'autres fichiers
window.auth = {
    authenticate,
    getLoginConfig,
    updateLoginConfig,
    isAuthenticated,
    logout,
    changePassword,
    addUser,
    removeUser,
    getUsers,
    isAdmin,
    protectAdminPage
};