/**
 * Module de requêtes préparées amélioré pour Tech Shield
 * Ce module fournit des fonctions robustes pour créer et exécuter des requêtes préparées
 * afin de prévenir les injections SQL
 */

window.preparedQueries = (function() {
    // Configuration des requêtes préparées
    const config = {
        // Type de base de données
        dbType: 'mysql', // 'mysql', 'postgresql', 'mongodb'
        
        // Délai d'expiration des requêtes en millisecondes
        queryTimeout: 5000,
        
        // Nombre maximal de tentatives en cas d'échec
        maxRetries: 3,
        
        // Délai entre les tentatives en millisecondes
        retryDelay: 1000,
        
        // Journalisation détaillée
        verboseLogging: true
    };
    
    // Stockage des requêtes préparées
    const preparedStatements = {};
    
    /**
     * Détecte les placeholders dans une requête SQL
     * @param {string} query - Requête SQL
     * @returns {Object} - Informations sur les placeholders
     */
    function detectPlaceholders(query) {
        if (!query) return { type: 'none', count: 0, names: [] };
        
        // Détecter les placeholders de type ? (MySQL style)
        const questionMarkCount = (query.match(/\?/g) || []).length;
        
        if (questionMarkCount > 0) {
            return { type: 'question_mark', count: questionMarkCount, names: [] };
        }
        
        // Détecter les placeholders de type :param (PostgreSQL style)
        const namedParams = query.match(/:[a-zA-Z0-9_]+/g) || [];
        
        if (namedParams.length > 0) {
            return {
                type: 'named',
                count: namedParams.length,
                names: namedParams.map(param => param.substring(1))
            };
        }
        
        // Détecter les placeholders de type $1, $2, etc. (PostgreSQL style)
        const numberedParams = query.match(/\$\d+/g) || [];
        
        if (numberedParams.length > 0) {
            return {
                type: 'numbered',
                count: numberedParams.length,
                names: numberedParams.map(param => param.substring(1))
            };
        }
        
        return { type: 'none', count: 0, names: [] };
    }
    
    /**
     * Prépare une requête SQL pour une utilisation ultérieure
     * @param {string} name - Nom unique de la requête préparée
     * @param {string} query - Requête SQL avec placeholders (? ou :param)
     * @param {Object} options - Options supplémentaires
     * @returns {Object} - Requête préparée
     */
    function prepareStatement(name, query, options = {}) {
        if (!name || !query) {
            throw new Error('Erreur de préparation de requête: Le nom et la requête SQL sont obligatoires. Veuillez fournir ces deux paramètres.');
        }
        
        // Détecter les placeholders dans la requête
        const placeholders = detectPlaceholders(query);
        
        // Créer la requête préparée
        const statement = {
            name,
            query,
            placeholders,
            options: {
                timeout: options.timeout || config.queryTimeout,
                maxRetries: options.maxRetries || config.maxRetries,
                retryDelay: options.retryDelay || config.retryDelay
            },
            metadata: { query }
        };
        
        // Stocker la requête préparée
        preparedStatements[name] = statement;
        
        if (config.verboseLogging) {
            console.log(`Requête préparée '${name}' créée avec ${placeholders.count} placeholders`);
        }
        
        return {
            name,
            placeholders,
            metadata: { query }
        };
    }
    
    /**
     * Exécute une requête préparée avec les paramètres fournis
     * @param {string} name - Nom de la requête préparée
     * @param {Array|Object} params - Paramètres pour la requête
     * @param {Object} options - Options supplémentaires
     * @returns {Promise} - Résultat de la requête
     */
    async function executeStatement(name, params = [], options = {}) {
        // Vérifier que la requête préparée existe
        if (!preparedStatements[name]) {
            throw new Error(`Erreur d'exécution: La requête préparée '${name}' n'existe pas. Veuillez d'abord créer cette requête avec prepareStatement() avant de l'exécuter.`);
        }
        
        const statement = preparedStatements[name];
        const execOptions = { ...statement.options, ...options };
        
        // Construire la requête finale avec les paramètres
        const finalQuery = buildFinalQuery(statement, params);
        
        // Journaliser l'exécution de la requête
        const logDetails = {
            timestamp: new Date().toISOString(),
            statement: name,
            query: statement.query,
            params,
            options: execOptions
        };
        
        if (config.verboseLogging) {
            logDetails.metadata = { finalQuery };
            console.log('Exécution de la requête préparée:', logDetails);
        }
        
        // Exécuter la requête
        try {
            return await executeWithRetry(finalQuery, execOptions);
        } catch (error) {
            console.error(`Erreur lors de l'exécution de la requête préparée '${name}':`, error);
            throw error;
        }
    }
    
    /**
     * Récupère une requête préparée par son nom
     * @param {string} name - Nom de la requête préparée
     * @returns {Object|null} - Requête préparée ou null si non trouvée
     */
    function getStatement(name) {
        if (!preparedStatements[name]) return null;
        
        const statement = preparedStatements[name];
        
        return {
            name: statement.name,
            query: statement.query,
            placeholders: statement.placeholders
        };
    }
    
    /**
     * Supprime une requête préparée
     * @param {string} name - Nom de la requête préparée
     * @returns {boolean} - true si supprimée, false sinon
     */
    function deleteStatement(name) {
        if (!preparedStatements[name]) return false;
        
        delete preparedStatements[name];
        return true;
    }
    
    /**
     * Liste toutes les requêtes préparées
     * @returns {Array} - Liste des requêtes préparées
     */
    function listStatements() {
        return Object.keys(preparedStatements).map(name => ({
            name,
            query: preparedStatements[name].query,
            placeholders: preparedStatements[name].placeholders
        }));
    }
    
    /**
     * Construit la requête finale avec les paramètres
     * @param {Object} statement - Requête préparée
     * @param {Array|Object} params - Paramètres pour la requête
     * @returns {Object} - Requête finale formatée
     */
    function buildFinalQuery(statement, params) {
        if (!statement) return null;
        
        const formattedParams = {};
        let query = statement.query;
        
        // Formater les paramètres selon le type de base de données
        switch (config.dbType.toLowerCase()) {
            case 'mysql':
                // Pour MySQL, remplacer les ? par les valeurs échappées
                if (Array.isArray(params)) {
                    formattedParams.values = params.map(sanitizeParam);
                    formattedParams.sql = query;
                } else if (typeof params === 'object') {
                    // Convertir les paramètres nommés en tableau
                    const values = [];
                    const regex = /:[a-zA-Z0-9_]+/g;
                    query = query.replace(regex, '?');
                    statement.placeholders.names.forEach(name => {
                        values.push(sanitizeParam(params[name]));
                    });
                    formattedParams.values = values;
                    formattedParams.sql = query;
                }
                break;
                
            case 'postgresql':
                // Pour PostgreSQL, utiliser $1, $2, etc.
                if (Array.isArray(params)) {
                    query = query.replace(/\?/g, (match, offset, string) => {
                        const index = string.substring(0, offset).split('?').length;
                        return `$${index}`;
                    });
                    formattedParams.text = query;
                    formattedParams.values = params.map(sanitizeParam);
                } else if (typeof params === 'object') {
                    // Convertir les paramètres nommés en paramètres numérotés
                    const values = [];
                    const paramMap = {};
                    let paramIndex = 1;
                    
                    statement.placeholders.names.forEach(name => {
                        paramMap[name] = paramIndex++;
                        values.push(sanitizeParam(params[name]));
                    });
                    
                    const regex = /:[a-zA-Z0-9_]+/g;
                    if (regex.test(query)) {
                        query = query.replace(regex, (match) => {
                            const key = match.substring(1);
                            return `$${paramMap[key]}`;
                        });
                    } else {
                        // Si la requête utilise déjà $1, $2, etc.
                        const numberedRegex = /\$\d+/g;
                        if (numberedRegex.test(query)) {
                            // Rien à faire, la requête est déjà au bon format
                        }
                    }
                    
                    formattedParams.text = query;
                    formattedParams.values = values;
                }
                break;
                
            default:
                formattedParams.query = query;
                formattedParams.params = params;
                break;
        }
        
        return formattedParams;
    }
    
    /**
     * Exécute une requête avec mécanisme de retry en cas d'échec
     * @param {Object} finalQuery - Requête finale formatée
     * @param {Object} options - Options d'exécution
     * @returns {Promise} - Résultat de la requête
     */
    async function executeWithRetry(finalQuery, options) {
        let retries = 0;
        let lastError = null;
        
        while (retries <= options.maxRetries) {
            try {
                const result = await simulateQueryExecution(finalQuery, options);
                return result;
            } catch (error) {
                lastError = error;
                
                // Si l'erreur est fatale, ne pas réessayer
                if (error.fatal) {
                    throw error;
                }
                
                retries++;
                
                if (retries <= options.maxRetries) {
                    // Attendre avant de réessayer
                    await new Promise(resolve => setTimeout(resolve, options.retryDelay));
                }
            }
        }
        
        // Si toutes les tentatives ont échoué, lancer l'erreur
        throw lastError || new Error(`Échec de l'exécution de la requête après ${options.maxRetries} tentatives. Veuillez vérifier la connexion à la base de données ou réessayer plus tard.`);
        
    }
    
    /**
     * Simule l'exécution d'une requête SQL (dans un environnement de production, cela serait remplacé par une vraie exécution)
     * @param {Object} finalQuery - Requête finale formatée
     * @param {Object} options - Options d'exécution
     * @returns {Promise} - Résultat de la requête
     */
    async function simulateQueryExecution(finalQuery, options) {
        // Dans un environnement de production, cette fonction serait remplacée par une vraie exécution de requête
        return new Promise((resolve, reject) => {
            // Simuler un délai d'exécution
            setTimeout(() => {
                // Simuler un résultat
                resolve({
                    success: true,
                    rows: [],
                    query: finalQuery
                });
            }, Math.random() * 100);
        });
    }
    
    /**
     * Sanitize un paramètre pour éviter les injections SQL
     * @param {*} param - Paramètre à sanitizer
     * @returns {*} - Paramètre sanitizé
     */
    function sanitizeParam(param) {
        if (param === null || param === undefined) {
            return null;
        }
        
        if (typeof param === 'string') {
            // Échapper les caractères spéciaux SQL
            return param
                .replace(/'/g, "''")
                .replace(/\\/g, "\\\\")
                .replace(/;/g, "");
        }
        
        if (param instanceof Date) {
            return param.toISOString();
        }
        
        return param;
    }
    
    /**
     * Initialise le module de requêtes préparées
     */
    function init() {
        console.log('Module de requêtes préparées initialisé');
    }
    
    // Initialiser le module au chargement
    init();
    
    // API publique
    return {
        prepareStatement,
        executeStatement,
        getStatement,
        deleteStatement,
        listStatements,
        sanitizeParam
    };
})();