package utils

import (
	"errors"

	"github.com/Snooker-IO/snooker-pkg/exceptions"
	"github.com/labstack/echo/v4"
)

type RequestError struct {
	StatusCode int
	Exception  exceptions.Exception
	Err        error
}

func (err RequestError) Error() string {
	return err.Exception.Message
}

func ResponseError(ctx echo.Context, err error) error {
	var requestError RequestError
	_ = errors.As(err, &requestError)

	return ctx.JSON(requestError.StatusCode, ErrorResponse{
		Status:  false,
		Message: requestError.Exception.Message,
		Code:    requestError.Exception.Code,
		Errors:  requestError.Err,
	})
}

func GetRequestError(err error) (RequestError, bool) {
	var reqErr RequestError
	isRequestErr := errors.As(err, &reqErr)

	return reqErr, isRequestErr
}

type ErrorResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code"`
	Errors  error  `json:"errors"`
}

type Response struct {
	Status   bool         `json:"status"`
	Response DataResponse `json:"response"`
}

type DataResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data"`
}
