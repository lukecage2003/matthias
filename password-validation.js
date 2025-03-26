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
    
    // Register form elements
    const registerForm = document.getElementById('registerForm');
    const registerEmail = document.getElementById('registerEmail');
    const registerName = document.getElementById('registerName');
    
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
            
            // In a real application, you would send this to a server for verification
            // This is just a simulation for demonstration purposes
            const email = loginEmail.value;
            const password = loginPassword.value;
            
            // Simulate authentication (replace with actual authentication)
            if (email === 'admin@techshield.com' && password === 'Admin@123456') {
                // Successful login
                loginAttempts = 0;
                alert('Connexion réussie!');
                // Redirect to dashboard or home page
                // window.location.href = 'dashboard.html';
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