// Module de requêtes préparées pour Tech Shield
// Implémentation de requêtes sécurisées pour éviter les injections SQL

/**
 * Configuration des requêtes préparées
 */
const preparedQueriesConfig = {
    // Type de base de données utilisé
    dbType: 'mysql', // 'mysql', 'postgresql', 'mongodb'
    
    // Activer la journalisation des requêtes
    logQueries: true,
    
    // Niveau de détail des logs (1: minimal, 2: standard, 3: détaillé)
    logLevel: 2,
    
    // Durée maximale d'exécution d'une requête (en ms)
    queryTimeout: 5000,
    
    // Nombre maximum de tentatives pour une requête
    maxRetries: 3,
    
    // Délai entre les tentatives (en ms)
    retryDelay: 1000,
    
    // Activer la validation des paramètres
    validateParams: true
};

// Stockage des requêtes préparées
const preparedStatements = {};

/**
 * Initialise le module de requêtes préparées
 * @param {Object} config - Configuration optionnelle
 * @returns {boolean} - Succès de l'initialisation
 */
function initPreparedQueries(config = {}) {
    try {
        // Fusionner la configuration fournie avec la configuration par défaut
        Object.assign(preparedQueriesConfig, config);
        
        console.log('Module de requêtes préparées initialisé');
        
        // Journaliser l'initialisation si le module de logs est disponible
        if (window.securityLogs && preparedQueriesConfig.logQueries) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: 'Module de requêtes préparées initialisé',
                source: 'prepared-queries'
            });
        }
        
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'initialisation du module de requêtes préparées:', error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: 'Échec de l\'initialisation du module de requêtes préparées: ' + error.message,
                source: 'prepared-queries'
            });
        }
        
        return false;
    }
}

/**
 * Prépare une requête SQL pour une utilisation ultérieure
 * @param {string} name - Nom unique de la requête préparée
 * @param {string} query - Requête SQL avec placeholders (? ou :param)
 * @param {Object} options - Options supplémentaires
 * @returns {Object} - Objet représentant la requête préparée
 */
function prepareStatement(name, query, options = {}) {
    try {
        // Vérifier si le nom est déjà utilisé
        if (preparedStatements[name]) {
            console.warn(`La requête préparée '${name}' existe déjà et sera remplacée`);
        }
        
        // Analyser la requête pour détecter les placeholders
        const placeholders = detectPlaceholders(query);
        
        // Créer l'objet de requête préparée
        const statement = {
            name,
            query,
            placeholders,
            options: Object.assign({
                timeout: preparedQueriesConfig.queryTimeout,
                maxRetries: preparedQueriesConfig.maxRetries,
                retryDelay: preparedQueriesConfig.retryDelay
            }, options),
            createdAt: new Date().toISOString()
        };
        
        // Stocker la requête préparée
        preparedStatements[name] = statement;
        
        // Journaliser la préparation si le module de logs est disponible
        if (window.securityLogs && preparedQueriesConfig.logQueries && preparedQueriesConfig.logLevel >= 2) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.INFO,
                details: `Requête préparée '${name}' créée`,
                source: 'prepared-queries',
                metadata: { query }
            });
        }
        
        return statement;
    } catch (error) {
        console.error(`Erreur lors de la préparation de la requête '${name}':`, error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: `Erreur lors de la préparation de la requête '${name}': ${error.message}`,
                source: 'prepared-queries',
                metadata: { query }
            });
        }
        
        throw error;
    }
}

/**
 * Détecte les placeholders dans une requête SQL
 * @param {string} query - Requête SQL
 * @returns {Array} - Liste des placeholders détectés
 */
function detectPlaceholders(query) {
    const placeholders = [];
    
    // Détecter les placeholders de type ? (MySQL style)
    const questionMarkCount = (query.match(/\?/g) || []).length;
    for (let i = 0; i < questionMarkCount; i++) {
        placeholders.push({ type: 'positional', index: i });
    }
    
    // Détecter les placeholders de type :param (PostgreSQL style)
    const namedParams = query.match(/:[a-zA-Z0-9_]+/g) || [];
    for (const param of namedParams) {
        const paramName = param.substring(1); // Enlever le :
        placeholders.push({ type: 'named', name: paramName });
    }
    
    return placeholders;
}

/**
 * Exécute une requête préparée avec les paramètres fournis
 * @param {string} name - Nom de la requête préparée
 * @param {Array|Object} params - Paramètres pour la requête (tableau pour positional, objet pour named)
 * @param {Object} options - Options d'exécution
 * @returns {Promise<Object>} - Résultat de la requête
 */
async function executeStatement(name, params = [], options = {}) {
    try {
        // Vérifier si la requête préparée existe
        const statement = preparedStatements[name];
        if (!statement) {
            throw new Error(`La requête préparée '${name}' n'existe pas. Veuillez d'abord créer cette requête avec prepareStatement() avant de l'exécuter.`);
        }
        
        // Fusionner les options
        const execOptions = Object.assign({}, statement.options, options);
        
        // Valider les paramètres si activé
        if (preparedQueriesConfig.validateParams) {
            validateParameters(statement, params);
        }
        
        // Construire la requête finale avec les paramètres
        const finalQuery = buildFinalQuery(statement, params);
        
        // Journaliser l'exécution si le module de logs est disponible
        if (window.securityLogs && preparedQueriesConfig.logQueries) {
            const logDetails = {
                status: window.securityLogs.LOG_TYPES.INFO,
                details: `Exécution de la requête préparée '${name}'`,
                source: 'prepared-queries'
            };
            
            // Ajouter des détails supplémentaires selon le niveau de log
            if (preparedQueriesConfig.logLevel >= 2) {
                logDetails.metadata = { 
                    query: statement.query,
                    paramCount: Array.isArray(params) ? params.length : Object.keys(params).length
                };
            }
            if (preparedQueriesConfig.logLevel >= 3) {
                logDetails.metadata.params = params;
                logDetails.metadata.finalQuery = finalQuery;
            }
            
            window.securityLogs.addLog(logDetails);
        }
        
        // Exécuter la requête avec gestion des tentatives
        return await executeWithRetry(finalQuery, execOptions);
    } catch (error) {
        console.error(`Erreur lors de l'exécution de la requête '${name}':`, error);
        
        // Journaliser l'erreur si le module de logs est disponible
        if (window.securityLogs) {
            window.securityLogs.addLog({
                status: window.securityLogs.LOG_TYPES.ERROR,
                details: `Erreur lors de l'exécution de la requête '${name}': ${error.message}`,
                source: 'prepared-queries',
                metadata: { 
                    query: preparedStatements[name]?.query,
                    error: error.message
                }
            });
        }
        
        throw error;
    }
}

/**
 * Valide les paramètres fournis pour une requête préparée
 * @param {Object} statement - Requête préparée
 * @param {Array|Object} params - Paramètres à valider
 * @throws {Error} - Si les paramètres sont invalides
 */
function validateParameters(statement, params) {
    const placeholders = statement.placeholders;
    const hasPositionalParams = placeholders.some(p => p.type === 'positional');
    const hasNamedParams = placeholders.some(p => p.type === 'named');
    const positionalCount = placeholders.filter(p => p.type === 'positional').length;
    
    // Valider le type de paramètres
    if (hasPositionalParams && !Array.isArray(params)) {
        throw new Error(`Erreur de type de paramètre: La requête '${statement.name}' attend des paramètres positionnels (tableau), mais a reçu un objet. Veuillez fournir un tableau de valeurs.`);
    }
    if (hasNamedParams && (typeof params !== 'object' || Array.isArray(params))) {
        throw new Error(`Erreur de type de paramètre: La requête '${statement.name}' attend des paramètres nommés (objet), mais a reçu un autre type. Veuillez fournir un objet avec les propriétés correspondant aux noms des paramètres.`);
    }
    
    // Valider le nombre de paramètres positionnels
    if (hasPositionalParams && params.length !== positionalCount) {
        throw new Error(`Erreur de nombre de paramètres: La requête '${statement.name}' attend ${positionalCount} paramètres, mais ${params.length} ont été fournis. Veuillez vérifier le nombre de paramètres.`);
    }
    
    // Valider la présence de tous les paramètres nommés
    if (hasNamedParams) {
        for (const param of statement.placeholders) {
            if (param.type === 'named' && params[param.name] === undefined) {
                throw new Error(`Paramètre manquant: Le paramètre nommé '${param.name}' est requis pour la requête '${statement.name}' mais n'a pas été fourni. Veuillez inclure ce paramètre.`);
            }
        }
    }
    
    // Vérifier qu'aucun paramètre n'est une fonction (risque d'injection)
    for (const key in params) {
        if (typeof params[key] === 'function') {
            throw new Error('Erreur de sécurité: Les fonctions ne sont pas autorisées comme paramètres de requête. Veuillez fournir uniquement des types de données simples (chaînes, nombres, booléens, etc.).');
        }
    }
}

/**
 * Construit la requête finale avec les paramètres
 * @param {Object} statement - Requête préparée
 * @param {Array|Object} params - Paramètres pour la requête
 * @returns {Object} - Requête finale et paramètres formatés
 */
function buildFinalQuery(statement, params) {
    // Note: Dans un environnement réel, cette fonction serait spécifique au type de base de données
    // et utiliserait les mécanismes de requêtes préparées natifs du SGBD.
    // Pour cette démonstration, nous simulons le comportement.
    
    let query = statement.query;
    const formattedParams = {};
    
    // Traiter selon le type de base de données configuré
    switch (preparedQueriesConfig.dbType) {
        case 'mysql':
            // Pour MySQL, remplacer les ? par les valeurs échappées
            if (Array.isArray(params)) {
                // Créer une copie de la requête pour la simulation
                formattedParams.sql = query;
                formattedParams.values = [...params];
            } else {
                // Remplacer les :param par les valeurs échappées
                for (const [key, value] of Object.entries(params)) {
                    const regex = new RegExp(`:${key}\\b`, 'g');
                    query = query.replace(regex, '?');
                }
                formattedParams.sql = query;
                formattedParams.values = Object.values(params);
            }
            break;
            
        case 'postgresql':
            // Pour PostgreSQL, utiliser $1, $2, etc.
            if (Array.isArray(params)) {
                query = query.replace(/\?/g, (match, offset, string) => {
                    const paramIndex = string.substring(0, offset).split('?').length;
                    return `$${paramIndex}`;
                });
                formattedParams.text = query;
                formattedParams.values = [...params];
            } else {
                let paramCounter = 1;
                const paramMap = {};
                
                // Remplacer les :param par $1, $2, etc.
                for (const key of Object.keys(params)) {
                    const regex = new RegExp(`:${key}\\b`, 'g');
                    if (regex.test(query)) {
                        paramMap[key] = paramCounter++;
                        query = query.replace(regex, `$${paramMap[key]}`);
                    }
                }
                
                // Réorganiser les valeurs selon l'ordre des paramètres
                const values = [];
                for (const [key, index] of Object.entries(paramMap)) {
                    values[index - 1] = params[key];
                }
                
                formattedParams.text = query;
                formattedParams.values = values;
            }
            break;
            
        case 'mongodb':
            // Pour MongoDB, utiliser un format d'objet de filtre
            formattedParams.query = query;
            formattedParams.params = params;
            break;
            
        default:
            throw new Error(`Type de base de données non pris en charge: ${preparedQueriesConfig.dbType}`);
    }
    
    return formattedParams;
}

/**
 * Exécute une requête avec gestion des tentatives
 * @param {Object} finalQuery - Requête finale formatée
 * @param {Object} options - Options d'exécution
 * @returns {Promise<Object>} - Résultat de la requête
 */
async function executeWithRetry(finalQuery, options) {
    let lastError = null;
    
    // Essayer d'exécuter la requête avec le nombre de tentatives spécifié
    for (let attempt = 1; attempt <= options.maxRetries; attempt++) {
        try {
            // Simuler l'exécution de la requête
            // Dans un environnement réel, cela appellerait la base de données
            const result = await simulateQueryExecution(finalQuery, options);
            
            // Journaliser le succès si le module de logs est disponible
            if (window.securityLogs && preparedQueriesConfig.logQueries && preparedQueriesConfig.logLevel >= 2) {
                window.securityLogs.addLog({
                    status: window.securityLogs.LOG_TYPES.INFO,
                    details: 'Requête exécutée avec succès',
                    source: 'prepared-queries',
                    metadata: { 
                        rowCount: result.rowCount || 0,
                        executionTime: result.executionTime
                    }
                });
            }
            
            return result;
        } catch (error) {
            lastError = error;
            
            // Journaliser l'échec si le module de logs est disponible
            if (window.securityLogs && preparedQueriesConfig.logQueries) {
                window.securityLogs.addLog({
                    status: window.securityLogs.LOG_TYPES.WARNING,
                    details: `Échec de l'exécution de la requête (tentative ${attempt}/${options.maxRetries}): ${error.message}`,
                    source: 'prepared-queries'
                });
            }
            
            // Si ce n'est pas la dernière tentative, attendre avant de réessayer
            if (attempt < options.maxRetries) {
                await new Promise(resolve => setTimeout(resolve, options.retryDelay));
            }
        }
    }
    
    // Si toutes les tentatives ont échoué, lancer l'erreur
    throw lastError || new Error(`Échec de l'exécution de la requête après ${options.maxRetries} tentatives. Veuillez vérifier la connexion à la base de données ou réessayer plus tard.`);
}

/**
 * Simule l'exécution d'une requête (pour la démonstration)
 * @param {Object} finalQuery - Requête finale formatée
 * @param {Object} options - Options d'exécution
 * @returns {Promise<Object>} - Résultat simulé de la requête
 */
async function simulateQueryExecution(finalQuery, options) {
    return new Promise((resolve, reject) => {
        // Simuler un délai d'exécution
        const executionTime = Math.floor(Math.random() * 100) + 50; // 50-150ms
        
        // Simuler un timeout
        const timeoutId = setTimeout(() => {
            reject(new Error(`La requête a dépassé le délai d'exécution de ${options.timeout}ms. Veuillez optimiser votre requête ou augmenter la valeur du timeout dans les options.`));
        }, options.timeout);
        
        // Simuler l'exécution
        setTimeout(() => {
            clearTimeout(timeoutId);
            
            // Simuler un résultat
            resolve({
                success: true,
                rowCount: Math.floor(Math.random() * 10),
                executionTime: executionTime,
                query: finalQuery
            });
        }, executionTime);
    });
}

/**
 * Crée et prépare des requêtes courantes pour les opérations CRUD
 * @param {string} tableName - Nom de la table
 * @returns {Object} - Objet contenant les requêtes CRUD préparées
 */
function prepareCRUDQueries(tableName) {
    const queries = {};
    
    // Requête SELECT
    queries.select = prepareStatement(
        `select_${tableName}`,
        `SELECT * FROM ${tableName} WHERE id = ?`
    );
    
    // Requête SELECT ALL
    queries.selectAll = prepareStatement(
        `select_all_${tableName}`,
        `SELECT * FROM ${tableName}`
    );
    
    // Requête INSERT (générique)
    queries.insert = prepareStatement(
        `insert_${tableName}`,
        `INSERT INTO ${tableName} (created_at, updated_at) VALUES (NOW(), NOW())`,
        { returnGeneratedKeys: true }
    );
    
    // Requête UPDATE
    queries.update = prepareStatement(
        `update_${tableName}`,
        `UPDATE ${tableName} SET updated_at = NOW() WHERE id = ?`
    );
    
    // Requête DELETE
    queries.delete = prepareStatement(
        `delete_${tableName}`,
        `DELETE FROM ${tableName} WHERE id = ?`
    );
    
    return queries;
}

// Exposer les fonctions publiques
window.preparedQueries = {
    init: initPreparedQueries,
    prepare: prepareStatement,
    execute: executeStatement,
    prepareCRUD: prepareCRUDQueries
};