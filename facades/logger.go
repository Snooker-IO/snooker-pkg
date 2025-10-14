package facades

import (
	"go.uber.org/zap"
)

type LoggerField = Field
type LoggerType int

const (
	LOGGER_ERROR  = LoggerType(1)
	LOGGER_STRING = LoggerType(2)
	LOGGER_ANY    = LoggerType(3)
	LOGGER_INT    = LoggerType(4)
)

type Field struct {
	Key       string
	Type      LoggerType
	Integer   int64
	String    string
	Interface interface{}
}

type LoggerFacadeInterface interface {
	Error(msg string, fields ...LoggerField)
	Info(msg string, fields ...LoggerField)
	Debug(msg string, fields ...LoggerField)
}

type LoggerFacade struct {
	zap *zap.Logger
}

func NewLoggerFacade(
	zap *zap.Logger,
) LoggerFacadeInterface {
	return LoggerFacade{
		zap: zap,
	}
}

func (facade LoggerFacade) Error(msg string, fields ...LoggerField) {
	fieldsZap := convertLoggerToZap(fields...)
	facade.zap.Error(msg, fieldsZap...)
}

func (facade LoggerFacade) Info(msg string, fields ...LoggerField) {
	fieldsZap := convertLoggerToZap(fields...)
	facade.zap.Info(msg, fieldsZap...)
}

func (facade LoggerFacade) Debug(msg string, fields ...LoggerField) {
	fieldsZap := convertLoggerToZap(fields...)
	facade.zap.Debug(msg, fieldsZap...)
}

func convertLoggerToZap(fields ...LoggerField) []zap.Field {
	var fieldsFormat []zap.Field
	for _, field := range fields {
		fieldsFormat = append(fieldsFormat, setLoggerField(field))
	}

	return fieldsFormat
}

func Error(value error) LoggerField {
	return LoggerField{Type: LOGGER_ERROR, Interface: value}
}

func String(key string, value string) LoggerField {
	return LoggerField{Key: key, Type: LOGGER_STRING, String: value}
}

func Any(key string, value interface{}) LoggerField {
	return LoggerField{Key: key, Type: LOGGER_ANY, Interface: value}
}

func Int(key string, value int) LoggerField {
	return LoggerField{Key: key, Type: LOGGER_INT, Interface: value}
}

func setLoggerField(log LoggerField) zap.Field {
	switch log.Type {
	case LOGGER_ERROR:
		return zap.Error(log.Interface.(error))
	case LOGGER_STRING:
		return zap.String(log.Key, log.String)
	case LOGGER_ANY:
		return zap.Any(log.Key, log.Interface)
	case LOGGER_INT:
		return zap.Int(log.Key, int(log.Integer))
	default:
		return zap.Any(log.Key, log.Interface)
	}
}
