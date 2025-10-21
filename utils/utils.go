package utils

import (
	"net/http"
	"strings"

	"github.com/Snooker-IO/snooker-pkg/exceptions"
)

func ParseBearerToken(token string) (string, error) {
	parts := strings.SplitN(token, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", RequestError{
			StatusCode: http.StatusBadRequest,
			Exception: exceptions.Exception{
				Message: "invalid Authorization header format",
				Code:    "AUTH_TOKEN_HEADER_INVALID",
			},
			Err: nil,
		}
	}

	return parts[1], nil
}
