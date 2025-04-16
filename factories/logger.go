package factories

import (
	"errors"

	"go.uber.org/zap"
)

type LoggerDriver int

const (
	ZapLoggerDriver = LoggerDriver(1)
)

type ZapLoggerConfig struct {
	CheckSyncErr bool
	ZapCfg       zap.Config
}
type ZapLogger struct {
	Zap *zap.Logger
}

type Logger struct {
	ZapLogger ZapLogger
}

type LoggerConfig struct {
	Driver    LoggerDriver
	ZapConfig ZapLoggerConfig
}

func (cfg LoggerConfig) LoggerFactory() Logger {
	switch cfg.Driver {
	case ZapLoggerDriver:
		return cfg.InitZapLogger()
	default:
		return Logger{}
	}
}

func (cfg LoggerConfig) InitZapLogger() Logger {
	logger, err := cfg.ZapConfig.ZapCfg.Build()
	if err != nil {
		panic(errors.New("error start logger"))
	}

	defer func() {
		err := logger.Sync()
		if cfg.ZapConfig.CheckSyncErr {
			if err != nil {
				panic(err)
			}
		}
	}()

	return Logger{
		ZapLogger: ZapLogger{
			Zap: logger,
		},
	}
}
