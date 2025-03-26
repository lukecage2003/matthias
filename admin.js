document.addEventListener("DOMContentLoaded", function() {
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
        });
    });

    // Gestion du bouton de déconnexion
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Simuler une déconnexion (dans un environnement réel, cela ferait appel à une API)
            // Supprimer les informations de session du localStorage
            localStorage.removeItem('isLoggedIn');
            localStorage.removeItem('username');
            
            // Rediriger vers la page de connexion
            window.location.href = 'login.html';
        });
    }

    // Configuration de l'authentification à deux facteurs
    const configureTwoFABtn = document.getElementById('configureTwoFA');
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

    // Vérification du code 2FA
    const verifyTwoFABtn = document.getElementById('verifyTwoFA');
    if (verifyTwoFABtn) {
        verifyTwoFABtn.addEventListener('click', function() {
            const code = document.getElementById('twofaCode').value;
            if (code && code.length === 6) {
                // Dans un environnement réel, cela vérifierait le code avec un serveur
                alert('Code vérifié avec succès!');
                twofaSetup.style.display = 'none';
                configureTwoFABtn.textContent = 'Configurer 2FA';
            } else {
                alert('Veuillez entrer un code à 6 chiffres valide.');
            }
        });
    }

    // Gestion de la liste blanche d'IP
    const addIPBtn = document.getElementById('addIP');
    const ipList = document.querySelector('.ip-list');
    
    if (addIPBtn && ipList) {
        // Ajouter une nouvelle IP
        addIPBtn.addEventListener('click', function() {
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