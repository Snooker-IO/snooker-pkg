package configs

import (
	"github.com/WV-Consultancy/pkg/factories"
	"go.uber.org/zap"
)

func GetLoggerConfig(env Environment) factories.LoggerConfig {
	var zapConfig factories.ZapLoggerConfig

	switch env {
	case DEVELOPMENT_ENVIRONMENT:
		zapConfig.ZapCfg = zap.NewProductionConfig()
		zapConfig.ZapCfg.DisableStacktrace = true
		zapConfig.ZapCfg.DisableCaller = true
		zapConfig.CheckSyncErr = false
	case PRODUCTION_ENVIRONMENT:
		zapConfig.CheckSyncErr = true
		zapConfig.ZapCfg = zap.NewProductionConfig()
		zapConfig.ZapCfg.DisableStacktrace = true
		zapConfig.ZapCfg.DisableCaller = true
	}

	return factories.LoggerConfig{
		Driver:    factories.ZapLoggerDriver,
		ZapConfig: zapConfig,
	}
}
