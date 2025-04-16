package utils

type ValidatorError struct {
	Field string `json:"field"`
	Error string `json:"error"`
}
type ValidateErrorRequest struct {
	Message string           `json:"-"`
	Data    []ValidatorError `json:"data"`
}

func (err ValidateErrorRequest) Error() string {
	return err.Message
}
