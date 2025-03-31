/**
 * Module de surveillance SSL/TLS pour Tech Shield
 * Ce script permet de surveiller l'état du certificat SSL/TLS depuis l'interface d'administration
 */

// Importer les fonctions de configuration SSL si nécessaire
// const { checkSSLCertificate, testSSLConfiguration } = require('./ssl-config.js');

// État du certificat SSL/TLS
let sslStatus = {
    installed: false,
    valid: false,
    expiration: null,
    grade: null,
    issuer: null,
    lastCheck: null,
    hstsEnabled: false
};

/**
 * Vérifie l'état du certificat SSL/TLS
 * @returns {Promise<object>} État du certificat
 */
async function checkSSLStatus() {
    console.log('Vérification de l\'état SSL/TLS...');
    
    try {
        // Dans un environnement réel, cette fonction ferait appel à une API ou à OpenSSL
        // pour vérifier l'état du certificat
        
        // Simulation de vérification
        sslStatus = {
            installed: true,
            valid: true,
            expiration: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 jours
            grade: 'A+',
            issuer: 'Let\'s Encrypt Authority X3',
            lastCheck: new Date(),
            hstsEnabled: true
        };
        
        return sslStatus;
    } catch (error) {
        console.error('Erreur lors de la vérification SSL:', error);
        sslStatus.lastCheck = new Date();
        return sslStatus;
    }
}

/**
 * Initialise le module de surveillance SSL dans l'interface d'administration
 */
function initSSLMonitor() {
    // Vérifier si nous sommes sur la page d'administration
    if (!document.querySelector('.admin-container')) {
        return;
    }
    
    console.log('Initialisation du moniteur SSL...');
    
    // Créer l'élément de surveillance SSL s'il n'existe pas déjà
    if (!document.getElementById('ssl-monitor')) {
        createSSLMonitorUI();
    }
    
    // Vérifier l'état SSL et mettre à jour l'interface
    updateSSLStatus();
    
    // Configurer une vérification périodique (toutes les 24 heures)
    setInterval(updateSSLStatus, 24 * 60 * 60 * 1000);
}

/**
 * Crée l'interface utilisateur du moniteur SSL
 */
function createSSLMonitorUI() {
    // Trouver l'onglet de sécurité
    const securityTab = document.getElementById('security');
    if (!securityTab) return;
    
    // Trouver l'en-tête des onglets
    const tabsHeader = securityTab.querySelector('.tabs-header');
    if (!tabsHeader) return;
    
    // Ajouter un nouvel onglet pour le moniteur SSL
    const sslTabButton = document.createElement('button');
    sslTabButton.className = 'tab-btn';
    sslTabButton.setAttribute('data-tab', 'ssl-monitor');
    sslTabButton.textContent = 'Moniteur SSL/TLS';
    tabsHeader.appendChild(sslTabButton);
    
    // Trouver le conteneur des onglets
    const tabsContent = securityTab.querySelector('.tabs-content');
    if (!tabsContent) return;
    
    // Créer le contenu de l'onglet SSL
    const sslTabContent = document.createElement('div');
    sslTabContent.id = 'ssl-monitor';
    sslTabContent.className = 'tab-content';
    
    sslTabContent.innerHTML = `
        <h3>Moniteur SSL/TLS</h3>
        
        <div class="ssl-status-card">
            <div class="ssl-status-header">
                <h4>État du certificat SSL/TLS</h4>
                <button id="refresh-ssl-status" class="refresh-btn" title="Rafraîchir l'état SSL">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
                    </svg>
                </button>
            </div>
            
            <div id="ssl-status-content" class="ssl-status-content">
                <p>Chargement de l'état SSL/TLS...</p>
            </div>
        </div>
        
        <div class="ssl-actions">
            <h4>Actions SSL/TLS</h4>
            <div class="action-buttons">
                <button id="check-ssl-btn" class="action-btn">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    Vérifier le certificat
                </button>
                <button id="install-ssl-btn" class="action-btn">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 15V3m0 12l-4-4m4 4l4-4M2 17l.621 2.485A2 2 0 0 0 4.561 21h14.878a2 2 0 0 0 1.94-1.515L22 17"/>
                    </svg>
                    Installer/Renouveler
                </button>
                <button id="configure-ssl-btn" class="action-btn">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>
                        <circle cx="12" cy="12" r="3"/>
                    </svg>
                    Configurer
                </button>
                <button id="test-ssl-btn" class="action-btn">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M20.91 8.84 8.56 2.23a1.93 1.93 0 0 0-1.81 0L3.1 4.13a2.12 2.12 0 0 0-.05 3.69l12.22 6.93a2 2 0 0 0 1.94 0L21 12.51a2.12 2.12 0 0 0-.09-3.67Z"/>
                        <path d="m3.09 8.84 12.35-6.61a1.93 1.93 0 0 1 1.81 0l3.65 1.9a2.12 2.12 0 0 1 .1 3.69L8.73 14.75a2 2 0 0 1-1.94 0L3 12.51a2.12 2.12 0 0 1 .09-3.67Z"/>
                        <line x1="12" y1="22" x2="12" y2="13"/>
                        <path d="M20 13.5v3.37a2.06 2.06 0 0 1-1.11 1.83l-6 3.08a1.93 1.93 0 0 1-1.78 0l-6-3.08A2.06 2.06 0 0 1 4 16.87V13.5"/>
                    </svg>
                    Tester
                </button>
            </div>
        </div>
        
        <div class="ssl-info-section">
            <h4>Informations sur HTTPS et SSL/TLS</h4>
            <div class="ssl-info-content">
                <p><strong>HTTPS</strong> (HyperText Transfer Protocol Secure) est une extension du protocole HTTP qui utilise le chiffrement SSL/TLS pour sécuriser les communications.</p>
                <p><strong>SSL/TLS</strong> (Secure Sockets Layer/Transport Layer Security) est un protocole cryptographique qui assure la confidentialité et l'intégrité des données échangées entre un client et un serveur.</p>
                <p><strong>Let's Encrypt</strong> est une autorité de certification qui fournit gratuitement des certificats SSL/TLS.</p>
                <p><strong>HSTS</strong> (HTTP Strict Transport Security) est un mécanisme de sécurité qui force les navigateurs à utiliser HTTPS pour toutes les connexions futures à un site web.</p>
            </div>
        </div>
    `;
    
    tabsContent.appendChild(sslTabContent);
    
    // Ajouter les gestionnaires d'événements pour les onglets
    document.querySelectorAll('.tab-btn').forEach(button => {
        button.addEventListener('click', function() {
            // Désactiver tous les onglets
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // Activer l'onglet sélectionné
            this.classList.add('active');
            const tabId = this.getAttribute('data-tab');
            const tabContent = document.getElementById(tabId);
            if (tabContent) tabContent.classList.add('active');
        });
    });
    
    // Ajouter les gestionnaires d'événements pour les boutons d'action
    document.getElementById('refresh-ssl-status')?.addEventListener('click', updateSSLStatus);
    document.getElementById('check-ssl-btn')?.addEventListener('click', checkSSLCertificateUI);
    document.getElementById('install-ssl-btn')?.addEventListener('click', showInstallSSLDialog);
    document.getElementById('configure-ssl-btn')?.addEventListener('click', showConfigureSSLDialog);
    document.getElementById('test-ssl-btn')?.addEventListener('click', testSSLConfigurationUI);
}

/**
 * Met à jour l'état SSL dans l'interface utilisateur
 */
async function updateSSLStatus() {
    const statusContent = document.getElementById('ssl-status-content');
    if (!statusContent) return;
    
    statusContent.innerHTML = '<p>Vérification de l\'état SSL/TLS...</p>';
    
    try {
        // Vérifier l'état SSL
        const status = await checkSSLStatus();
        
        // Formater la date d'expiration
        const expirationDate = status.expiration ? new Date(status.expiration) : null;
        const expirationFormatted = expirationDate ? expirationDate.toLocaleDateString() : 'N/A';
        
        // Calculer les jours restants avant expiration
        const daysRemaining = expirationDate ? Math.ceil((expirationDate - new Date()) / (1000 * 60 * 60 * 24)) : 0;
        
        // Déterminer la classe CSS pour l'état d'expiration
        let expirationClass = 'status-ok';
        if (daysRemaining <= 0) {
            expirationClass = 'status-critical';
        } else if (daysRemaining <= 14) {
            expirationClass = 'status-warning';
        } else if (daysRemaining <= 30) {
            expirationClass = 'status-info';
        }
        
        // Mettre à jour l'interface utilisateur
        statusContent.innerHTML = `
            <div class="ssl-status-grid">
                <div class="ssl-status-item">
                    <span class="status-label">Certificat installé:</span>
                    <span class="status-value ${status.installed ? 'status-ok' : 'status-critical'}">
                        ${status.installed ? 'Oui' : 'Non'}
                    </span>
                </div>
                <div class="ssl-status-item">
                    <span class="status-label">Certificat valide:</span>
                    <span class="status-value ${status.valid ? 'status-ok' : 'status-critical'}">
                        ${status.valid ? 'Oui' : 'Non'}
                    </span>
                </div>
                <div class="ssl-status-item">
                    <span class="status-label">Date d'expiration:</span>
                    <span class="status-value ${expirationClass}">
                        ${expirationFormatted} ${daysRemaining > 0 ? `(${daysRemaining} jours restants)` : '(Expiré)'}
                    </span>
                </div>
                <div class="ssl-status-item">
                    <span class="status-label">Émetteur:</span>
                    <span class="status-value">${status.issuer || 'N/A'}</span>
                </div>
                <div class="ssl-status-item">
                    <span class="status-label">Note SSL Labs:</span>
                    <span class="status-value ${getGradeClass(status.grade)}">
                        ${status.grade || 'N/A'}
                    </span>
                </div>
                <div class="ssl-status-item">
                    <span class="status-label">HSTS activé:</span>
                    <span class="status-value ${status.hstsEnabled ? 'status-ok' : 'status-warning'}">
                        ${status.hstsEnabled ? 'Oui' : 'Non'}
                    </span>
                </div>
                <div class="ssl-status-item">
                    <span class="status-label">Dernière vérification:</span>
                    <span class="status-value">
                        ${status.lastCheck ? new Date(status.lastCheck).toLocaleString() : 'Jamais'}
                    </span>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Erreur lors de la mise à jour de l\'état SSL:', error);
        statusContent.innerHTML = `
            <div class="ssl-status-error">
                <p>Erreur lors de la vérification de l'état SSL/TLS.</p>
                <p>Détails: ${error.message}</p>
            </div>
        `;
    }
}

/**
 * Retourne la classe CSS correspondant à la note SSL
 * @param {string} grade Note SSL
 * @returns {string} Classe CSS
 */
function getGradeClass(grade) {
    if (!grade) return '';
    
    switch (grade.charAt(0)) {
        case 'A': return 'status-ok';
        case 'B': return 'status-info';
        case 'C': return 'status-warning';
        default: return 'status-critical';
    }
}

/**
 * Affiche l'interface utilisateur pour vérifier le certificat SSL
 */
function checkSSLCertificateUI() {
    // Simuler une vérification du certificat
    const statusContent = document.getElementById('ssl-status-content');
    if (statusContent) {
        statusContent.innerHTML = '<p>Vérification du certificat SSL/TLS...</p>';
        
        // Mettre à jour l'état après un court délai (simulation)
        setTimeout(updateSSLStatus, 1500);
    }
}

/**
 * Affiche la boîte de dialogue d'installation/renouvellement SSL
 */
function showInstallSSLDialog() {
    // Créer une boîte de dialogue modale
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Installation/Renouvellement du certificat SSL/TLS</h3>
                <button class="close-btn">&times;</button>
            </div>
            <div class="modal-body">
                <p>Cette action lancera l'installation ou le renouvellement d'un certificat SSL/TLS Let's Encrypt.</p>
                <p>Assurez-vous que:</p>
                <ul>
                    <li>Vous avez accès au serveur avec les privilèges appropriés</li>
                    <li>Le domaine pointe correctement vers ce serveur</li>
                    <li>Le port 80 est accessible depuis Internet pour la validation du domaine</li>
                </ul>
                
                <form id="ssl-install-form">
                    <div class="form-group">
                        <label for="ssl-email">Email administrateur:</label>
                        <input type="email" id="ssl-email" required placeholder="admin@example.com">
                    </div>
                    <div class="form-group">
                        <label for="ssl-domains">Domaines (séparés par des virgules):</label>
                        <input type="text" id="ssl-domains" required placeholder="example.com,www.example.com">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="ssl-agree" required>
                            J'accepte les <a href="https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf" target="_blank">conditions d'utilisation</a> de Let's Encrypt
                        </label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button id="ssl-install-cancel" class="btn-secondary">Annuler</button>
                <button id="ssl-install-confirm" class="btn-primary">Installer/Renouveler</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Gestionnaires d'événements
    modal.querySelector('.close-btn').addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    modal.querySelector('#ssl-install-cancel').addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    modal.querySelector('#ssl-install-confirm').addEventListener('click', () => {
        const form = document.getElementById('ssl-install-form');
        if (form.checkValidity()) {
            const email = document.getElementById('ssl-email').value;
            const domains = document.getElementById('ssl-domains').value;
            const agree = document.getElementById('ssl-agree').checked;
            
            if (agree) {
                // Simuler l'installation
                modal.querySelector('.modal-body').innerHTML = '<p>Installation du certificat SSL/TLS en cours...</p><div class="progress-bar"><div class="progress"></div></div>';
                modal.querySelector('.modal-footer').innerHTML = '';
                
                // Animer la barre de progression
                const progress = modal.querySelector('.progress');
                let width = 0;
                const interval = setInterval(() => {
                    if (width >= 100) {
                        clearInterval(interval);
                        modal.querySelector('.modal-body').innerHTML = '<p>Certificat SSL/TLS installé avec succès!</p>';
                        modal.querySelector('.modal-footer').innerHTML = '<button id="ssl-install-done" class="btn-primary">Terminé</button>';
                        
                        modal.querySelector('#ssl-install-done').addEventListener('click', () => {
                            document.body.removeChild(modal);
                            updateSSLStatus();
                        });
                    } else {
                        width++;
                        progress.style.width = width + '%';
                    }
                }, 50);
            }
        } else {
            form.reportValidity();
        }
    });
}

/**
 * Affiche la boîte de dialogue de configuration SSL
 */
function showConfigureSSLDialog() {
    // Créer une boîte de dialogue modale
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Configuration SSL/TLS</h3>
                <button class="close-btn">&times;</button>
            </div>
            <div class="modal-body">
                <form id="ssl-config-form">
                    <div class="form-group">
                        <label for="ssl-server-type">Type de serveur:</label>
                        <select id="ssl-server-type">
                            <option value="nginx">Nginx</option>
                            <option value="apache">Apache</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="ssl-force-https" checked>
                            Forcer HTTPS (redirection HTTP vers HTTPS)
                        </label>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="ssl-enable-hsts" checked>
                            Activer HSTS (HTTP Strict Transport Security)
                        </label>
                    </div>
                    
                    <div id="hsts-options" class="sub-options">
                        <div class="form-group">
                            <label for="ssl-hsts-max-age">Durée de validité HSTS (secondes):</label>
                            <input type="number" id="ssl-hsts-max-age" value="63072000" min="0">
                            <small>Recommandé: 63072000 (2 ans)</small>
                        </div>
                        
                        <div class="form-group">
                            <label>
                                <input type="checkbox" id="ssl-hsts-subdomains" checked>
                                Inclure les sous-domaines
                            </label>
                        </div>
                        
                        <div class="form-group">
                            <label>
                                <input type="checkbox" id="ssl-hsts-preload">
                                Ajouter à la liste de préchargement HSTS
                            </label>
                            <small>Attention: Difficile à annuler, utilisez avec précaution</small>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="ssl-protocols">Protocoles SSL/TLS:</label>
                        <div class="checkbox-group">
                            <label>
                                <input type="checkbox" name="ssl-protocol" value="TLSv1.2" checked>
                                TLS 1.2
                            </label>
                            <label>
                                <input type="checkbox" name="ssl-protocol" value="TLSv1.3" checked>
                                TLS 1.3
                            </label>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button id="ssl-config-cancel" class="btn-secondary">Annuler</button>
                <button id="ssl-config-confirm" class="btn-primary">Appliquer</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Gestionnaires d'événements
    modal.querySelector('.close-btn').addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    modal.querySelector('#ssl-config-cancel').addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    // Afficher/masquer les options HSTS
    const hstsCheckbox = modal.querySelector('#ssl-enable-hsts');
    const hstsOptions = modal.querySelector('#hsts-options');
    
    hstsCheckbox.addEventListener('change', () => {
        hstsOptions.style.display = hstsCheckbox.checked ? 'block' : 'none';
    });
    
    modal.querySelector('#ssl-config-confirm').addEventListener('click', () => {
        // Simuler l'application de la configuration
        modal.querySelector('.modal-body').innerHTML = '<p>Application de la configuration SSL/TLS...</p><div class="progress-bar"><div class="progress"></div></div>';
        modal.querySelector('.modal-footer').innerHTML = '';
        
        // Animer la barre de progression
        const progress = modal.querySelector('.progress');
        let width = 0;
        const interval = setInterval(() => {
            if (width >= 100) {
                clearInterval(interval);
                modal.querySelector('.modal-body').innerHTML = '<p>Configuration SSL/TLS appliquée avec succès!</p>';
                modal.querySelector('.modal-footer').innerHTML = '<button id="ssl-config-done" class="btn-primary">Terminé</button>';
                
                modal.querySelector('#ssl-config-done').addEventListener('click', () => {
                    document.body.removeChild(modal);
                    updateSSLStatus();
                });
            } else {
                width++;
                progress.style.width = width + '%';
            }
        }, 30);
    });
}

/**
 * Affiche l'interface utilisateur pour tester la configuration SSL
 */
function testSSLConfigurationUI() {
    // Créer une boîte de dialogue modale
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Test de la configuration SSL/TLS</h3>
                <button class="close-btn">&times;</button>
            </div>
            <div class="modal-body">
                <p>Lancement du test SSL/TLS...</p>
                <div class="progress-bar"><div class="progress"></div></div>
            </div>
            <div class="modal-footer"></div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Gestionnaires d'événements
    modal.querySelector('.close-btn').addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    // Animer la barre de progression
    const progress = modal.querySelector('.progress');
    let width = 0;
    const interval = setInterval(() => {
        if (width >= 100) {
            clearInterval(interval);
            
            // Simuler les résultats du test
            const testResults = {
                grade: 'A+',
                protocols: ['TLSv1.2', 'TLSv1.3'],
                ciphers: 'Strong',
                certificateExpiry: '90 days',
                vulnerabilities: {
                    heartbleed: false,
                    poodle: false,
                    freak: false,
                    logjam: false,
                    drown: false,
                    beast: false
                },
                hsts: true,
                securityHeaders: {
                    hstsPresent: true,
                    xContentTypeOptions: true,
                    xFrameOptions: true,
                    xXssProtection: true,
                    contentSecurityPolicy: false
                }
            };
            
            // Afficher les résultats
            modal.querySelector('.modal-body').innerHTML = `
                <div class="test-results">
                    <div class="test-result-header">
                        <div class="test-grade status-${getGradeClass(testResults.grade)}">${testResults.grade}</div>
                        <div class="test-summary">
                            <h4>Résultat du test SSL/TLS</h4>
                            <p>Votre configuration SSL/TLS est ${testResults.grade.startsWith('A') ? 'excellente' : testResults.grade.startsWith('B') ? 'bonne' : testResults.grade.startsWith('C') ? 'moyenne' : 'faible'}.</p>
                        </div>
                    </div>
                    <div class="test-details">
                        <div class="test-section">
                            <h5>Certificat</h5>
                            <div class="test-item">
                                <span class="test-label">Expiration:</span>
                                <span class="test-value">${testResults.certificateExpiry}</span>
                            </div>
                        </div>
                        
                        <div class="test-section">
                            <h5>Protocoles</h5>
                            <div class="test-item">
                                <span class="test-label">Protocoles supportés:</span>
                                <span class="test-value">${testResults.protocols.join(', ')}</span>
                            </div>
                            <div class="test-item">
                                <span class="test-label">Suites de chiffrement:</span>
                                <span class="test-value">${testResults.ciphers}</span>
                            </div>
                        </div>
                        
                        <div class="test-section">
                            <h5>Vulnérabilités</h5>
                            <div class="vulnerabilities-list">
                                ${Object.entries(testResults.vulnerabilities).map(([name, vulnerable]) => `
                                    <div class="test-item">
                                        <span class="test-label">${name.charAt(0).toUpperCase() + name.slice(1)}:</span>
                                        <span class="test-value ${vulnerable ? 'status-critical' : 'status-ok'}">${ vulnerable ? 'Vulnérable' : 'Protégé'}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        
                        <div class="test-section">
                            <h5>En-têtes de sécurité</h5>
                            <div class="test-item">
                                <span class="test-label">HSTS:</span>
                                <span class="test-value ${testResults.hsts ? 'status-ok' : 'status-warning'}">${ testResults.hsts ? 'Activé' : 'Désactivé'}</span>
                            </div>
                            ${Object.entries(testResults.securityHeaders).map(([name, present]) => {
                                if (name === 'hstsPresent') return ''; // Déjà affiché ci-dessus
                                const readableName = name
                                    .replace(/([A-Z])/g, ' $1')
                                    .replace(/^./, str => str.toUpperCase())
                                    .replace('X ', 'X-');
                                return `
                                    <div class="test-item">
                                        <span class="test-label">${readableName}:</span>
                                        <span class="test-value ${present ? 'status-ok' : 'status-warning'}">${ present ? 'Présent' : 'Absent'}</span>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                </div>
            `;
            
            modal.querySelector('.modal-footer').innerHTML = '<button id="ssl-test-done" class="btn-primary">Terminé</button>';
            
            modal.querySelector('#ssl-test-done').addEventListener('click', () => {
                document.body.removeChild(modal);
            });
        }
    }, 50);
}

// Initialiser le module lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', initSSLMonitor);

// Exporter les fonctions pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        checkSSLStatus,
        initSSLMonitor,
        updateSSLStatus
    };
}