/**
 * Script d'installation et de configuration SSL/TLS pour Tech Shield
 * Ce script utilise le module ssl-config.js pour installer et configurer SSL/TLS
 */

const readline = require('readline');
const { sslConfig, checkSSLCertificate, installLetsEncrypt, configureServer, testSSLConfiguration, initSSL } = require('./ssl-config.js');

// Interface de ligne de commande
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

/**
 * Affiche le menu principal
 */
function showMenu() {
    console.log('\n=== Tech Shield - Installation SSL/TLS ===');
    console.log('1. Vérifier si un certificat SSL/TLS est installé');
    console.log('2. Installer un certificat Let\'s Encrypt');
    console.log('3. Configurer le serveur web pour HTTPS');
    console.log('4. Activer HSTS');
    console.log('5. Tester la configuration SSL/TLS');
    console.log('6. Installation complète (étapes 1-5)');
    console.log('7. Modifier les paramètres');
    console.log('8. Quitter');
    console.log('=========================================');
    
    rl.question('Choisissez une option (1-8): ', handleMenuChoice);
}

/**
 * Gère le choix de l'utilisateur dans le menu
 * @param {string} choice Choix de l'utilisateur
 */
async function handleMenuChoice(choice) {
    switch (choice) {
        case '1':
            await checkSSLCertificate();
            waitForKeyPress();
            break;
        case '2':
            await installLetsEncrypt();
            waitForKeyPress();
            break;
        case '3':
            rl.question('Type de serveur (nginx/apache): ', async (serverType) => {
                if (serverType === 'nginx' || serverType === 'apache') {
                    await configureServer(serverType);
                } else {
                    console.log('Type de serveur non valide. Utilisation de la valeur par défaut:', sslConfig.server.type);
                    await configureServer();
                }
                waitForKeyPress();
            });
            return;
        case '4':
            await configureHSTS();
            waitForKeyPress();
            break;
        case '5':
            const results = await testSSLConfiguration();
            console.log('\nRésultats détaillés:');
            console.log(JSON.stringify(results, null, 2));
            waitForKeyPress();
            break;
        case '6':
            await initSSL();
            waitForKeyPress();
            break;
        case '7':
            modifySettings();
            return;
        case '8':
            console.log('Au revoir!');
            rl.close();
            return;
        default:
            console.log('Option non valide. Veuillez réessayer.');
            showMenu();
            return;
    }
}

/**
 * Configure HSTS (HTTP Strict Transport Security)
 */
async function configureHSTS() {
    console.log('\n=== Configuration HSTS ===');
    console.log('HSTS force les navigateurs à utiliser HTTPS pour toutes les connexions futures.');
    
    rl.question('Activer HSTS? (oui/non): ', async (answer) => {
        if (answer.toLowerCase() === 'oui') {
            sslConfig.server.hsts.enabled = true;
            
            rl.question('Durée de validité en secondes (recommandé: 63072000 pour 2 ans): ', (maxAge) => {
                const maxAgeNum = parseInt(maxAge);
                if (!isNaN(maxAgeNum) && maxAgeNum > 0) {
                    sslConfig.server.hsts.maxAge = maxAgeNum;
                }
                
                rl.question('Inclure les sous-domaines? (oui/non): ', (includeSubDomains) => {
                    sslConfig.server.hsts.includeSubDomains = includeSubDomains.toLowerCase() === 'oui';
                    
                    rl.question('Ajouter à la liste de préchargement HSTS? (oui/non): ', (preload) => {
                        sslConfig.server.hsts.preload = preload.toLowerCase() === 'oui';
                        
                        console.log('\nConfiguration HSTS mise à jour:');
                        console.log(JSON.stringify(sslConfig.server.hsts, null, 2));
                        
                        // Reconfigurer le serveur avec les nouveaux paramètres HSTS
                        configureServer().then(() => {
                            waitForKeyPress();
                        });
                    });
                });
            });
            return;
        } else {
            sslConfig.server.hsts.enabled = false;
            console.log('HSTS désactivé.');
            waitForKeyPress();
        }
    });
}

/**
 * Modifie les paramètres de configuration
 */
function modifySettings() {
    console.log('\n=== Modification des paramètres ===');
    console.log('1. Paramètres du certificat');
    console.log('2. Paramètres du serveur');
    console.log('3. Retour au menu principal');
    
    rl.question('Choisissez une option (1-3): ', (choice) => {
        switch (choice) {
            case '1':
                modifyCertificateSettings();
                break;
            case '2':
                modifyServerSettings();
                break;
            case '3':
                showMenu();
                break;
            default:
                console.log('Option non valide. Retour au menu principal.');
                showMenu();
                break;
        }
    });
}

/**
 * Modifie les paramètres du certificat
 */
function modifyCertificateSettings() {
    console.log('\n=== Paramètres du certificat ===');
    console.log('Paramètres actuels:');
    console.log(JSON.stringify(sslConfig.certificate, null, 2));
    
    rl.question('Email administrateur: ', (email) => {
        if (email) sslConfig.certificate.email = email;
        
        rl.question('Domaines (séparés par des virgules): ', (domains) => {
            if (domains) sslConfig.certificate.domains = domains.split(',').map(d => d.trim());
            
            rl.question('Taille de clé RSA (2048/4096): ', (rsaKeySize) => {
                const keySize = parseInt(rsaKeySize);
                if (!isNaN(keySize) && (keySize === 2048 || keySize === 4096)) {
                    sslConfig.certificate.rsaKeySize = keySize;
                }
                
                console.log('\nParamètres du certificat mis à jour:');
                console.log(JSON.stringify(sslConfig.certificate, null, 2));
                
                waitForKeyPress();
            });
        });
    });
}

/**
 * Modifie les paramètres du serveur
 */
function modifyServerSettings() {
    console.log('\n=== Paramètres du serveur ===');
    console.log('Paramètres actuels:');
    console.log(JSON.stringify(sslConfig.server, null, 2));
    
    rl.question('Type de serveur (nginx/apache): ', (serverType) => {
        if (serverType === 'nginx' || serverType === 'apache') {
            sslConfig.server.type = serverType;
        }
        
        rl.question('Forcer HTTPS (oui/non): ', (forceHttps) => {
            sslConfig.server.forceHttps = forceHttps.toLowerCase() === 'oui';
            
            console.log('\nParamètres du serveur mis à jour:');
            console.log(JSON.stringify(sslConfig.server, null, 2));
            
            waitForKeyPress();
        });
    });
}

/**
 * Attend que l'utilisateur appuie sur une touche pour continuer
 */
function waitForKeyPress() {
    rl.question('\nAppuyez sur Entrée pour continuer...', () => {
        showMenu();
    });
}

// Démarrer le programme
console.log('Tech Shield - Utilitaire d'installation SSL/TLS');
console.log('Ce script vous guidera à travers le processus d'installation et de configuration SSL/TLS.');
console.log('\nNote: Dans un environnement de production, ce script doit être exécuté avec les privilèges appropriés.');

showMenu();