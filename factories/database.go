package factories

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/gorm/logger"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DatabaseDriver string

const (
	POSTGRES_DRIVER    = DatabaseDriver("postgres")
	POSTGRES_TX_DRIVER = DatabaseDriver("postgresTx")
)

type MongoConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	DSN      string
	Database string
}

type PostgresConfig struct {
	Host     string
	Username string
	Password string
	Database string
	Port     string
	TimeZone string
	SSLMode  string
}

type PostgresDB struct {
	ReadOnly *gorm.DB
	WriteDB  *gorm.DB
}
type Database struct {
	Postgres PostgresDB
}

type DatabaseConfig struct {
	Driver   DatabaseDriver
	Postgres PostgresConfig
}

func (db DatabaseConfig) DatabaseFactory() Database {
	switch db.Driver {
	case POSTGRES_DRIVER:
		return db.ConnectPostgres()
	case POSTGRES_TX_DRIVER:
		return db.ConnectPostgresTransaction()
	default:
		return Database{}
	}
}

func (db DatabaseConfig) ConnectPostgres() Database {
	dsn := fmt.Sprintf(
		`host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s`,
		db.Postgres.Host,
		db.Postgres.Username,
		db.Postgres.Password,
		db.Postgres.Database,
		db.Postgres.Port,
		db.Postgres.SSLMode,
		db.Postgres.TimeZone,
	)

	connect, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		SkipDefaultTransaction: true,
	})
	if err != nil {
		panic("error connect postgres database")
	}

	return Database{
		Postgres: PostgresDB{
			ReadOnly: connect,
			WriteDB:  connect,
		},
	}
}

func (db DatabaseConfig) ConnectPostgresTransaction() Database {
	dsn := fmt.Sprintf(
		`host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s`,
		db.Postgres.Host,
		db.Postgres.Username,
		db.Postgres.Password,
		db.Postgres.Database,
		db.Postgres.Port,
		db.Postgres.SSLMode,
		db.Postgres.TimeZone,
	)

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // gravador io
		logger.Config{
			SlowThreshold:             time.Second,   // Limite de lentidão do SQL
			LogLevel:                  logger.Silent, // Nível de log
			IgnoreRecordNotFoundError: true,          // Ignorar erro ErrRecordNotFound para o registrador
			ParameterizedQueries:      true,          // Não incluir parâmetros no log SQL
			Colorful:                  false,         // Desativar cor
		},
	)

	connect, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:                 newLogger,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		panic("error connect postgres database")
	}

	tx := connect.Begin()
	return Database{
		Postgres: PostgresDB{
			ReadOnly: connect,
			WriteDB:  tx,
		},
	}
}
