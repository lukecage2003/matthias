document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const registerPassword = document.getElementById('registerPassword');
    const confirmPassword = document.getElementById('confirmPassword');
    const passwordMatchMessage = document.getElementById('password-match-message');
    const strengthBar = document.querySelector('.strength-bar');
    const registerButton = document.getElementById('registerButton');
    
    // Password requirement elements
    const lengthReq = document.getElementById('length');
    const uppercaseReq = document.getElementById('uppercase');
    const lowercaseReq = document.getElementById('lowercase');
    const numberReq = document.getElementById('number');
    const specialReq = document.getElementById('special');
    
    // Login form elements
    const loginForm = document.getElementById('loginForm');
    const loginEmail = document.getElementById('loginEmail');
    const loginPassword = document.getElementById('loginPassword');
    const loginMessage = document.getElementById('loginMessage');
    
    // Register form elements
    const registerForm = document.getElementById('registerForm');
    const registerEmail = document.getElementById('registerEmail');
    const registerName = document.getElementById('registerName');
    
    // Gestion de la soumission du formulaire de connexion
    if (loginForm) {
        // Ajouter un compteur de tentatives sous le formulaire
        const attemptCounter = document.createElement('div');
        attemptCounter.className = 'attempt-counter';
        loginForm.appendChild(attemptCounter);
        
        // Fonction pour mettre à jour le compteur de tentatives
        function updateAttemptCounter(email) {
            if (window.loginSecurity && window.loginSecurity.getRemainingAttempts) {
                const remainingAttempts = window.loginSecurity.getRemainingAttempts(email);
                attemptCounter.textContent = `Tentatives restantes: ${remainingAttempts}`;
                
                // Ajouter une classe d'avertissement si le nombre de tentatives est faible
                if (remainingAttempts <= window.loginSecurity.config.warningThreshold) {
                    attemptCounter.classList.add('warning');
                } else {
                    attemptCounter.classList.remove('warning');
                }
                
                attemptCounter.style.display = 'block';
            } else {
                attemptCounter.style.display = 'none';
            }
        }
        
        // Mettre à jour le compteur lorsque l'email change
        loginEmail.addEventListener('blur', function() {
            const email = this.value.trim();
            if (email) {
                updateAttemptCounter(email);
            }
        });
        
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const email = loginEmail.value.trim();
            const password = loginPassword.value;
            
            // Mettre à jour le compteur de tentatives
            updateAttemptCounter(email);
            
            // Utiliser la fonction d'authentification
            const authResult = window.auth && window.auth.authenticate(email, password);
            
            if (authResult && authResult.success) {
                // Afficher le bouton d'administration si l'utilisateur est admin
                const adminButtonContainer = document.getElementById('adminButtonContainer');
                if (window.auth.isAdmin() && adminButtonContainer) {
                    adminButtonContainer.style.display = 'block';
                    loginMessage.textContent = 'Connexion réussie. Vous pouvez accéder à l\'administration.';
                    loginMessage.style.display = 'block';
                    loginMessage.style.color = 'green';
                    loginMessage.style.marginTop = '10px';
                } else {
                    window.location.href = 'index.html';
                }
            } else if (authResult && authResult.requireTwoFA) {
                // Afficher un formulaire pour le code 2FA
                const twoFAForm = document.createElement('div');
                twoFAForm.className = 'form-group';
                twoFAForm.innerHTML = `
                    <label for="twoFACode">Code d'authentification à deux facteurs :</label>
                    <input type="text" id="twoFACode" name="twoFACode" placeholder="Entrez le code à 6 chiffres" required>
                    <button type="button" id="submitTwoFA" class="auth-btn">Vérifier</button>
                `;
                
                // Ajouter le formulaire après le bouton de connexion
                loginForm.appendChild(twoFAForm);
                
                // Gérer la soumission du code 2FA
                document.getElementById('submitTwoFA').addEventListener('click', function() {
                    const twoFACode = document.getElementById('twoFACode').value;
                    const twoFAResult = window.auth.authenticate(email, password, twoFACode);
                    
                    if (twoFAResult && twoFAResult.success) {
                        if (window.auth.isAdmin()) {
                            adminButtonContainer.style.display = 'block';
                            loginMessage.textContent = 'Connexion réussie. Vous pouvez accéder à l\'administration.';
                            loginMessage.style.display = 'block';
                            loginMessage.style.color = 'green';
                        } else {
                            window.location.href = 'index.html';
                        }
                    } else if (twoFAResult && twoFAResult.invalidTwoFA) {
                        loginMessage.textContent = 'Code d\'authentification invalide. Veuillez réessayer.';
                        loginMessage.style.display = 'block';
                        loginMessage.style.color = 'red';
                    }
                });
                
                loginMessage.textContent = 'Veuillez entrer le code d\'authentification à deux facteurs.';
                loginMessage.style.display = 'block';
                loginMessage.style.color = 'blue';
            } else if (authResult && authResult.locked) {
                // Compte verrouillé
                const lockTime = new Date(authResult.lockedUntil);
                const now = new Date();
                const minutesLeft = Math.ceil((lockTime - now) / 60000);
                
                loginMessage.textContent = `Compte temporairement verrouillé. Réessayez dans ${minutesLeft} minute(s).`;
                loginMessage.style.display = 'block';
                loginMessage.style.color = 'red';
                loginMessage.classList.add('shake-animation');
            } else if (authResult && authResult.ipBlocked) {
                // IP bloquée par le système de sécurité
                const blockStatus = authResult.blockStatus;
                const minutesLeft = blockStatus.remainingMinutes;
                const attempts = blockStatus.attempts || 1;
                
                let message = `Adresse IP temporairement bloquée suite à trop de tentatives échouées. `;
                message += `Réessayez dans ${minutesLeft} minute(s).`;
                
                if (attempts > 1) {
                    message += ` Ceci est votre ${attempts}e blocage.`;
                }
                
                loginMessage.textContent = message;
                loginMessage.style.display = 'block';
                loginMessage.style.color = 'red';
                loginMessage.classList.add('shake-animation');
            } else if (authResult && authResult.warning) {
                // Avertissement avant blocage
                loginMessage.textContent = authResult.reason;
                loginMessage.style.display = 'block';
                loginMessage.style.color = 'orange';
            } else if (authResult && authResult.ipNotAllowed) {
                // IP non autorisée
                loginMessage.textContent = 'Accès refusé depuis cette adresse IP.';
                loginMessage.style.display = 'block';
                loginMessage.style.color = 'red';
            } else {
                // Afficher un message d'erreur général
                loginMessage.textContent = 'Email ou mot de passe incorrect';
                loginMessage.style.display = 'block';
                loginMessage.style.color = 'red';
                loginMessage.style.marginTop = '10px';
            }
        });
    }
    
    // Tab switching function
    window.showTab = function(tabId) {
        // Hide all tabs
        document.querySelectorAll('.auth-form').forEach(form => {
            form.classList.remove('active');
        });
        
        // Show selected tab
        document.getElementById(tabId).classList.add('active');
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        
        // Find the button that triggered this and activate it
        document.querySelectorAll('.tab-btn').forEach(btn => {
            if (btn.getAttribute('onclick').includes(tabId)) {
                btn.classList.add('active');
            }
        });
    };
    
    // Password validation
    function validatePassword(password) {
        const requirements = {
            length: password.length >= 12,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[!@#$%^&*]/.test(password)
        };
        
        // Update UI for each requirement
        lengthReq.classList.toggle('valid', requirements.length);
        uppercaseReq.classList.toggle('valid', requirements.uppercase);
        lowercaseReq.classList.toggle('valid', requirements.lowercase);
        numberReq.classList.toggle('valid', requirements.number);
        specialReq.classList.toggle('valid', requirements.special);
        
        // Calculate strength percentage
        const metRequirements = Object.values(requirements).filter(Boolean).length;
        const strengthPercentage = (metRequirements / 5) * 100;
        
        // Update strength bar
        strengthBar.style.width = `${strengthPercentage}%`;
        
        // Set color based on strength
        if (strengthPercentage < 40) {
            strengthBar.style.backgroundColor = '#dc3545'; // Red
        } else if (strengthPercentage < 80) {
            strengthBar.style.backgroundColor = '#ffc107'; // Yellow
        } else {
            strengthBar.style.backgroundColor = '#28a745'; // Green
        }
        
        // Return true if all requirements are met
        return Object.values(requirements).every(Boolean);
    }
    
    // Check if passwords match
    function checkPasswordsMatch() {
        const password = registerPassword.value;
        const confirmPwd = confirmPassword.value;
        
        if (confirmPwd.length === 0) {
            passwordMatchMessage.textContent = '';
            return false;
        }
        
        if (password === confirmPwd) {
            passwordMatchMessage.textContent = 'Les mots de passe correspondent';
            passwordMatchMessage.className = 'match-success';
            return true;
        } else {
            passwordMatchMessage.textContent = 'Les mots de passe ne correspondent pas';
            passwordMatchMessage.className = 'match-error';
            return false;
        }
    }
    
    // Update register button state
    function updateRegisterButtonState() {
        const isPasswordValid = validatePassword(registerPassword.value);
        const doPasswordsMatch = checkPasswordsMatch();
        const isNameValid = registerName.value.trim().length > 0;
        const isEmailValid = registerEmail.value.trim().length > 0 && registerEmail.validity.valid;
        
        registerButton.disabled = !(isPasswordValid && doPasswordsMatch && isNameValid && isEmailValid);
    }
    
    // Event listeners for password validation
    if (registerPassword) {
        registerPassword.addEventListener('input', function() {
            validatePassword(this.value);
            if (confirmPassword.value.length > 0) {
                checkPasswordsMatch();
            }
            updateRegisterButtonState();
        });
    }
    
    if (confirmPassword) {
        confirmPassword.addEventListener('input', function() {
            checkPasswordsMatch();
            updateRegisterButtonState();
        });
    }
    
    if (registerName) {
        registerName.addEventListener('input', updateRegisterButtonState);
    }
    
    if (registerEmail) {
        registerEmail.addEventListener('input', updateRegisterButtonState);
    }
    
    // Login attempt tracking
    let loginAttempts = 0;
    const maxLoginAttempts = 5;
    let lockoutTime = null;
    
    // Check if user is locked out
    function isLockedOut() {
        if (lockoutTime && new Date() < lockoutTime) {
            const remainingTime = Math.ceil((lockoutTime - new Date()) / 1000 / 60);
            return `Trop de tentatives échouées. Réessayez dans ${remainingTime} minute(s).`;
        }
        return false;
    }
    
    // Handle login form submission
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Check if user is locked out
            const lockoutMessage = isLockedOut();
            if (lockoutMessage) {
                alert(lockoutMessage);
                return;
            }
            
            // Vérifier le jeton CSRF si le module est disponible
            if (window.csrf) {
                const formId = this.id;
                const csrfInput = this.querySelector('input[name="csrf_token"]');
                
                if (!csrfInput || !window.csrf.validateCSRFToken(formId, csrfInput.value)) {
                    alert('Erreur de sécurité: jeton CSRF invalide. Veuillez rafraîchir la page et réessayer.');
                    return;
                }
            }
            
            // In a real application, you would send this to a server for verification
            // This is just a simulation for demonstration purposes
            const email = loginEmail.value;
            const password = loginPassword.value;
            
            // Utiliser la fonction d'authentification
            const authResult = window.auth && window.auth.authenticate(email, password);
            if (authResult && authResult.success) {
                // Successful login
                loginAttempts = 0;
                
                // Afficher le bouton d'administration si l'utilisateur est admin
                const adminButtonContainer = document.getElementById('adminButtonContainer');
                if (window.auth.isAdmin() && adminButtonContainer) {
                    adminButtonContainer.style.display = 'block';
                    loginMessage.textContent = 'Connexion réussie. Vous pouvez accéder à l\'administration.';
                    loginMessage.style.display = 'block';
                    loginMessage.style.color = 'green';
                    loginMessage.style.marginTop = '10px';
                    alert('Connexion réussie! Vous pouvez accéder à l\'administration.');
                } else {
                    window.location.href = 'index.html';
                }
            } else {
                // Failed login
                loginAttempts++;
                
                if (loginAttempts >= maxLoginAttempts) {
                    // Lock out user for 15 minutes
                    lockoutTime = new Date(new Date().getTime() + 15 * 60000);
                    alert(`Trop de tentatives échouées. Compte verrouillé pendant 15 minutes.`);
                } else {
                    alert(`Identifiants incorrects. Tentative ${loginAttempts}/${maxLoginAttempts}.`);
                }
            }
        });
    }
    
    // Handle register form submission
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // In a real application, you would send this to a server for account creation
            // This is just a simulation for demonstration purposes
            alert('Inscription réussie! Vous pouvez maintenant vous connecter.');
            
            // Clear form and switch to login tab
            registerForm.reset();
            showTab('login');
        });
    }
});