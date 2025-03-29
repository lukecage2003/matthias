document.addEventListener("DOMContentLoaded", function() {
    // Protéger la page d'administration
    if (window.auth) {
        window.auth.protectAdminPage();
    } else {
        window.location.href = 'login.html';
        return;
    }
    
    // Charger les journaux de sécurité
    loadSecurityLogs();
    
    // Initialiser la surveillance des logs en temps réel
    initRealtimeLogs();
    
    // Charger les alertes de sécurité
    loadSecurityAlerts();
    
    // Initialiser la surveillance des alertes en temps réel
    initRealtimeAlerts();
    
    // Les informations de l'utilisateur connecté ont été supprimées
    // Fonction pour charger et afficher les logs de sécurité
    function loadSecurityLogs() {
        const logTableBody = document.querySelector('.log-table tbody');
        if (!logTableBody || !window.securityLogs) return;
        
        // Vider le tableau actuel
        logTableBody.innerHTML = '';
        
        // Obtenir tous les logs
        const logs = window.securityLogs.getAllLogs();
        
        // Trier les logs par date (du plus récent au plus ancien)
        logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Ajouter chaque log au tableau
        logs.forEach(log => {
            const row = document.createElement('tr');
            
            // Formater la date
            const date = new Date(log.timestamp);
            const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
            
            // Déterminer la classe CSS pour le statut
            let statusClass = 'log-info';
            let statusText = 'Info';
            
            switch(log.status) {
                case window.securityLogs.LOG_TYPES.SUCCESS:
                    statusClass = 'log-success';
                    statusText = 'Succès';
                    break;
                case window.securityLogs.LOG_TYPES.FAILURE:
                    statusClass = 'log-failed';
                    statusText = 'Échec';
                    break;
                case window.securityLogs.LOG_TYPES.SUSPICIOUS:
                    statusClass = 'log-suspicious';
                    statusText = 'Suspect';
                    break;
                case window.securityLogs.LOG_TYPES.WARNING:
                    statusClass = 'log-warning';
                    statusText = 'Avertissement';
                    break;
            }
            
            // Construire la ligne du tableau
            row.innerHTML = `
                <td>${formattedDate}</td>
                <td>${log.email || 'N/A'}</td>
                <td>${log.ipAddress}</td>
                <td><span class="log-status ${statusClass}">${statusText}</span></td>
                <td>${log.details}</td>
            `;
            
            logTableBody.appendChild(row);
        });
    }
    
    // Fonction pour initialiser la surveillance des connexions en temps réel
    function initRealtimeLogs() {
        const realtimeLogsContainer = document.getElementById('realtimeLogs');
        if (!realtimeLogsContainer || !window.securityLogs) return;
        
        // S'abonner aux événements de connexion
        const subscriptionId = window.securityLogs.subscribeToLoginEvents(function(log) {
            // Créer un élément pour le nouveau log
            const logItem = document.createElement('div');
            logItem.className = 'realtime-log-item new';
            
            // Formater la date
            const date = new Date(log.timestamp);
            const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
            
            // Déterminer la classe CSS pour le statut
            let statusClass = 'log-info';
            let statusText = 'Info';
            
            switch(log.status) {
                case window.securityLogs.LOG_TYPES.SUCCESS:
                    statusClass = 'log-success';
                    statusText = 'Succès';
                    break;
                case window.securityLogs.LOG_TYPES.FAILURE:
                    statusClass = 'log-failed';
                    statusText = 'Échec';
                    break;
                case window.securityLogs.LOG_TYPES.SUSPICIOUS:
                    statusClass = 'log-suspicious';
                    statusText = 'Suspect';
                    break;
                case window.securityLogs.LOG_TYPES.WARNING:
                    statusClass = 'log-warning';
                    statusText = 'Avertissement';
                    break;
            }
            
            // Construire le contenu du log
            logItem.innerHTML = `
                <div class="log-header">
                    <div>
                        <span class="log-user">${log.email || 'Utilisateur inconnu'}</span>
                        <span class="log-ip">${log.ipAddress}</span>
                    </div>
                    <span class="log-time">${formattedDate}</span>
                </div>
                <div class="log-message">
                    <span class="log-status ${statusClass}">${statusText}</span> ${log.details}
                </div>
            `;
            
            // Supprimer le message "En attente d'activité" s'il existe
            const noLogsMessage = realtimeLogsContainer.querySelector('.no-logs-message');
            if (noLogsMessage) {
                realtimeLogsContainer.removeChild(noLogsMessage);
            }
            
            // Ajouter le nouveau log au début du conteneur
            realtimeLogsContainer.insertBefore(logItem, realtimeLogsContainer.firstChild);
            
            // Limiter le nombre de logs affichés à 10
            const logItems = realtimeLogsContainer.querySelectorAll('.realtime-log-item');
            if (logItems.length > 10) {
                realtimeLogsContainer.removeChild(logItems[logItems.length - 1]);
            }
            
            // Mettre à jour également le tableau des logs historiques
            loadSecurityLogs();
        });
        
        // Se désabonner lorsque l'utilisateur quitte la page
        window.addEventListener('beforeunload', function() {
            if (window.securityLogs && window.securityLogs.unsubscribeFromLoginEvents) {
                window.securityLogs.unsubscribeFromLoginEvents(subscriptionId);
            }
        });
    }
    
    // Gestion des onglets de l'interface d'administration
    const tabLinks = document.querySelectorAll('.admin-nav a');
    const tabContents = document.querySelectorAll('.admin-tab');

    tabLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Retirer la classe active de tous les liens et contenus
            tabLinks.forEach(l => l.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Ajouter la classe active au lien cliqué
            this.classList.add('active');
            
            // Afficher le contenu correspondant
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
            
            // Recharger les logs si on est sur l'onglet de sécurité
            if (tabId === 'security') {
                loadSecurityLogs();
            }
        });
    });
    
    // Gestionnaire pour le bouton d'actualisation des logs
    const refreshLogsBtn = document.getElementById('refreshLogs');
    if (refreshLogsBtn) {
        refreshLogsBtn.addEventListener('click', function() {
            loadSecurityLogs();
        });
    }
    
    // Gestionnaire pour le filtre de type de logs
    const logTypeFilter = document.getElementById('logTypeFilter');
    if (logTypeFilter) {
        logTypeFilter.addEventListener('change', function() {
            loadSecurityLogs();
        });
    }

    // Gestion du bouton de déconnexion
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Utiliser la fonction de déconnexion
            if (window.auth) {
                window.auth.logout();
            } else {
                window.location.href = 'login.html';
            }
        });
    }

    // Configuration de l'authentification à deux facteurs
    const configureTwoFABtn = document.getElementById('configureTwoFA');
    const disableTwoFABtn = document.getElementById('disableTwoFA');
    const twofaSetup = document.getElementById('twofaSetup');
    
    if (configureTwoFABtn && twofaSetup) {
        configureTwoFABtn.addEventListener('click', function() {
            if (twofaSetup.style.display === 'none' || twofaSetup.style.display === '') {
                twofaSetup.style.display = 'flex';
                this.textContent = 'Annuler';
            } else {
                twofaSetup.style.display = 'none';
                this.textContent = 'Configurer 2FA';
            }
        });
    }
    
    // Gestion du bouton de désactivation 2FA
    if (disableTwoFABtn) {
        disableTwoFABtn.addEventListener('click', function() {
            const userEmail = sessionStorage.getItem('userEmail');
            
            if (userEmail && window.twoFA) {
                if (window.twoFA.disableTwoFA(userEmail)) {
                    // Mettre à jour le statut 2FA dans l'interface
                    const twofaStatus = document.getElementById('twofaStatus');
                    if (twofaStatus) {
                        twofaStatus.textContent = 'Désactivé';
                        twofaStatus.className = 'status-disabled';
                    }
                    alert('L\'authentification à deux facteurs a été désactivée avec succès!');
                }
            }
        });
    }

    // Vérification du code 2FA
    const verifyTwoFABtn = document.getElementById('verifyTwoFA');
    if (verifyTwoFABtn) {
        verifyTwoFABtn.addEventListener('click', function() {
            const code = document.getElementById('twofaCode').value;
            const userEmail = sessionStorage.getItem('userEmail');
            
            if (code && code.length === 6 && userEmail) {
                // Vérifier le code avec la fonction du module twoFA
                if (window.twoFA && window.twoFA.verifyTOTP(userEmail, code)) {
                    alert('Code vérifié avec succès!');
                    twofaSetup.style.display = 'none';
                    configureTwoFABtn.textContent = 'Configurer 2FA';
                    
                    // Mettre à jour le statut 2FA dans l'interface
                    const twofaStatus = document.getElementById('twofaStatus');
                    if (twofaStatus) {
                        twofaStatus.textContent = 'Activé';
                        twofaStatus.className = 'status-enabled';
                    }
                } else {
                    alert('Code 2FA invalide. Veuillez réessayer.');
                }
            } else {
                alert('Veuillez entrer un code à 6 chiffres valide.');
            }
        });
    }

    // Gestion des paramètres de tentatives de connexion
    const saveLoginAttemptsBtn = document.getElementById('saveLoginAttempts');
    const maxAttemptsInput = document.getElementById('maxAttempts');
    const lockoutTimeInput = document.getElementById('lockoutTime');
    
    if (saveLoginAttemptsBtn && maxAttemptsInput && lockoutTimeInput) {
        // Initialiser les valeurs avec les paramètres actuels
        if (window.auth && window.auth.getLoginConfig) {
            const config = window.auth.getLoginConfig();
            maxAttemptsInput.value = config.maxAttempts;
            lockoutTimeInput.value = config.lockoutTime;
        }
        
        // Enregistrer les nouveaux paramètres
        saveLoginAttemptsBtn.addEventListener('click', function() {
            const maxAttempts = parseInt(maxAttemptsInput.value);
            const lockoutTime = parseInt(lockoutTimeInput.value);
            
            if (maxAttempts >= 1 && maxAttempts <= 10 && lockoutTime >= 5 && lockoutTime <= 60) {
                if (window.auth && window.auth.updateLoginConfig) {
                    window.auth.updateLoginConfig(maxAttempts, lockoutTime);
                    alert('Paramètres de tentatives de connexion mis à jour avec succès!');
                }
            } else {
                alert('Veuillez entrer des valeurs valides (tentatives: 1-10, durée: 5-60 minutes).');
            }
        });
    }
    
    // Gestion de la liste blanche d'IP
    const addIPBtn = document.getElementById('addIP');
    const ipList = document.querySelector('.ip-list');
    
    if (addIPBtn && ipList) {
        // Charger la liste des IP autorisées
        function loadIPWhitelist() {
            // Vider la liste actuelle
            ipList.innerHTML = '';
            
            if (window.ipWhitelist) {
                const whitelistedIPs = window.ipWhitelist.getAllWhitelistedIPs();
                
                whitelistedIPs.forEach(entry => {
                    const ipItem = document.createElement('div');
                    ipItem.className = 'ip-item';
                    ipItem.innerHTML = `
                        <span>${entry.ip}</span>
                        <div class="ip-actions">
                            <button class="remove-ip" data-ip="${entry.ip}">Supprimer</button>
                        </div>
                    `;
                    ipList.appendChild(ipItem);
                });
                
                // Ajouter les écouteurs d'événements pour les boutons de suppression
                document.querySelectorAll('.remove-ip').forEach(button => {
                    button.addEventListener('click', function() {
                        const ip = this.getAttribute('data-ip');
                        if (window.ipWhitelist.removeFromWhitelist(ip)) {
                            loadIPWhitelist(); // Recharger la liste
                        }
                    });
                });
            }
        }
        
        // Charger la liste initiale
        loadIPWhitelist();
        
        // Ajouter une nouvelle IP
        addIPBtn.addEventListener('click', function() {
            const newIPInput = document.getElementById('newIP');
            const ipAddress = newIPInput.value.trim();
            
            // Validation simple d'adresse IP (pourrait être améliorée)
            const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            
            if (ipPattern.test(ipAddress)) {
                if (window.ipWhitelist) {
                    const userEmail = sessionStorage.getItem('userEmail') || 'admin@techshield.com';
                    const added = window.ipWhitelist.addToWhitelist(ipAddress, 'Ajouté manuellement', userEmail);
                    
                    if (added) {
                        newIPInput.value = ''; // Effacer l'input
                        loadIPWhitelist(); // Recharger la liste
                        alert('Adresse IP ajoutée à la liste blanche avec succès!');
                    } else {
                        alert('Cette adresse IP est déjà dans la liste blanche.');
                    }
                }
            } else {
                alert('Veuillez entrer une adresse IP valide (format: xxx.xxx.xxx.xxx).');
            }
            const newIPInput = document.getElementById('newIP');
            const ipValue = newIPInput.value.trim();
            
            // Validation simple d'IP (pourrait être améliorée)
            const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            if (ipPattern.test(ipValue)) {
                // Créer un nouvel élément IP
                const ipItem = document.createElement('div');
                ipItem.className = 'ip-item';
                ipItem.innerHTML = `
                    <span>${ipValue}</span>
                    <div class="ip-actions">
                        <button class="remove-ip">Supprimer</button>
                    </div>
                `;
                
                // Ajouter à la liste
                ipList.appendChild(ipItem);
                
                // Réinitialiser l'input
                newIPInput.value = '';
                
                // Ajouter l'événement de suppression
                const removeBtn = ipItem.querySelector('.remove-ip');
                removeBtn.addEventListener('click', function() {
                    ipItem.remove();
                });
            } else {
                alert('Veuillez entrer une adresse IP valide.');
            }
        });
        
        // Gérer les boutons de suppression existants
        document.querySelectorAll('.remove-ip').forEach(btn => {
            btn.addEventListener('click', function() {
                this.closest('.ip-item').remove();
            });
        });
        
        // Gestion des utilisateurs
        const userList = document.getElementById('userList');
        const addUserForm = document.getElementById('addUserForm');
        const updateUserForm = document.getElementById('updateUserForm');
        const editUserForm = document.getElementById('editUserForm');
        const cancelEditBtn = document.getElementById('cancelEditBtn');
        
        // Fonction pour afficher la liste des utilisateurs
        function displayUsers() {
            if (!userList || !window.auth) return;
            
            // Vider la liste actuelle
            userList.innerHTML = '';
            
            // Récupérer la liste des utilisateurs
            const users = window.auth.getUsers();
            
            // Afficher chaque utilisateur
            for (const email in users) {
                const userItem = document.createElement('div');
                userItem.className = 'user-item';
                userItem.innerHTML = `
                    <div class="user-info">
                        <span class="user-email">${email}</span>
                        <span class="user-role">${users[email].role}</span>
                        <span class="user-last-login">${users[email].lastLogin || 'Jamais connecté'}</span>
                    </div>
                    <div class="user-actions">
                        <button class="edit-user" data-email="${email}">Modifier</button>
                        <button class="remove-user" data-email="${email}">Supprimer</button>
                    </div>
                `;
                
                userList.appendChild(userItem);
            }
            
            // Ajouter les événements pour les boutons d'édition et de suppression
            document.querySelectorAll('.edit-user').forEach(btn => {
                btn.addEventListener('click', function() {
                    const email = this.getAttribute('data-email');
                    showEditUserForm(email);
                });
            });
            
            document.querySelectorAll('.remove-user').forEach(btn => {
                btn.addEventListener('click', function() {
                    const email = this.getAttribute('data-email');
                    if (confirm(`Êtes-vous sûr de vouloir supprimer l'utilisateur ${email} ?`)) {
                        if (window.auth.removeUser(email)) {
                            displayUsers(); // Rafraîchir la liste
                        }
                    }
                });
            });
        }
        
        // Fonction pour afficher le formulaire d'édition
        function showEditUserForm(email) {
            if (!editUserForm) return;
            
            // Afficher le formulaire
            editUserForm.style.display = 'block';
            
            // Remplir les champs
            document.getElementById('editUserEmail').value = email;
            document.getElementById('editUserPassword').value = '';
            
            // Sélectionner le rôle actuel
            const users = window.auth.getUsers();
            if (users[email]) {
                document.getElementById('editUserRole').value = users[email].role;
            }
        }
        
        // Événement pour le formulaire d'ajout d'utilisateur
        if (addUserForm) {
            addUserForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                // Vérifier le jeton CSRF si le module est disponible
                if (window.csrf) {
                    const formId = this.id;
                    const csrfInput = this.querySelector('input[name="csrf_token"]');
                    
                    if (!csrfInput || !window.csrf.validateCSRFToken(formId, csrfInput.value)) {
                        alert('Erreur de sécurité: jeton CSRF invalide. Veuillez rafraîchir la page et réessayer.');
                        return;
                    }
                }
                
                const email = document.getElementById('newUserEmail').value.trim();
                const password = document.getElementById('newUserPassword').value;
                const role = document.getElementById('newUserRole').value;
                
                if (window.auth.addUser(email, password, role)) {
                    // Réinitialiser le formulaire
                    this.reset();
                    
                    // Rafraîchir la liste des utilisateurs
                    displayUsers();
                    
                    alert(`L'utilisateur ${email} a été ajouté avec succès.`);
                } else {
                    alert(`L'utilisateur ${email} existe déjà.`);
                }
            });
        }
        
        // Événement pour le formulaire de mise à jour d'utilisateur
        if (updateUserForm) {
            updateUserForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const email = document.getElementById('editUserEmail').value;
                const password = document.getElementById('editUserPassword').value;
                
                if (window.auth.changePassword(email, password)) {
                    // Masquer le formulaire
                    editUserForm.style.display = 'none';
                    
                    // Rafraîchir la liste des utilisateurs
                    displayUsers();
                    
                    alert(`Le mot de passe de l'utilisateur ${email} a été mis à jour.`);
                } else {
                    alert(`Une erreur est survenue lors de la mise à jour.`);
                }
            });
        }
        
        // Événement pour le bouton d'annulation
        if (cancelEditBtn) {
            cancelEditBtn.addEventListener('click', function() {
                editUserForm.style.display = 'none';
            });
        }
        
        // Afficher la liste des utilisateurs au chargement
        if (userList && window.auth) {
            displayUsers();
        }
    }

    // Gestion des paramètres de tentatives de connexion
    const saveLoginAttemptsBtn = document.getElementById('saveLoginAttempts');
    if (saveLoginAttemptsBtn) {
        saveLoginAttemptsBtn.addEventListener('click', function() {
            const maxAttempts = document.getElementById('maxAttempts').value;
            const lockoutTime = document.getElementById('lockoutTime').value;
            
            // Dans un environnement réel, cela enverrait les données à un serveur
            alert(`Paramètres enregistrés: ${maxAttempts} tentatives max, verrouillage de ${lockoutTime} minutes.`);
        });
    }

    // Afficher les informations de l'utilisateur admin
    const adminUsername = document.getElementById('adminUsername');
    const lastLogin = document.getElementById('lastLogin');
    
    if (adminUsername && lastLogin) {
        // Dans un environnement réel, ces informations viendraient d'une API
        const username = localStorage.getItem('username') || 'Admin';
        adminUsername.textContent = username;
        
        // Formater la date actuelle pour simuler la dernière connexion
        const now = new Date();
        const formattedDate = `${now.getDate().toString().padStart(2, '0')}/${(now.getMonth() + 1).toString().padStart(2, '0')}/${now.getFullYear()} ${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
        lastLogin.textContent = `Dernière connexion: ${formattedDate}`;
    }
});