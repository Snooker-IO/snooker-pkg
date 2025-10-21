package middlewares

import (
	"context"
	"net/http"
	"strings"

	"github.com/Snooker-IO/snooker-pkg/adapters/dtos"
	"github.com/Snooker-IO/snooker-pkg/exceptions"
	"github.com/Snooker-IO/snooker-pkg/facades"
	"github.com/Snooker-IO/snooker-pkg/factories"
	"github.com/Snooker-IO/snooker-pkg/repositories"
	"github.com/Snooker-IO/snooker-pkg/repositories/provider"
	"github.com/Snooker-IO/snooker-pkg/utils"
	"github.com/labstack/echo/v4"
)

type AuthMiddleware struct {
	database     factories.DatabaseConfig
	logger       factories.LoggerConfig
	auth         factories.AuthConfig
	authFacade   facades.AuthFacadeInterface
	loggerFacade facades.LoggerFacadeInterface
}

func NewAuthMiddleware(
	database factories.DatabaseConfig,
	logger factories.LoggerConfig,
	auth factories.AuthConfig,
) *AuthMiddleware {
	return &AuthMiddleware{
		database: database,
		logger:   logger,
		auth:     auth,
	}
}

func (md *AuthMiddleware) CheckRoutePermission(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		routePath := c.Path()
		md.auth.Driver = factories.AUTH_KEYCLOAK_DRIVER
		md.database.Driver = factories.POSTGRES_DRIVER
		md.logger.Driver = factories.ZapLoggerDriver

		md.loggerFacade = facades.NewLoggerFacade(md.logger.LoggerFactory().ZapLogger.Zap)
		md.authFacade = facades.NewAuthFacade(md.auth.AuthFactory(), md.loggerFacade)
		connectDB := md.database.DatabaseFactory()
		provs := md.loadProvider(connectDB)

		routeRepo := provs.RouteRepositoryProvider()
		route, err := routeRepo.FindByPath(c.Request().Context(), routePath)
		if err != nil {
			return utils.ResponseError(c, utils.RequestError{
				StatusCode: http.StatusInternalServerError,
				Exception:  exceptions.Exception{},
				Err:        err,
			})
		}

		if !route.Auth {
			return next(c)
		}

		userRepo := provs.UserRepositoryProvider()
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return utils.ResponseError(c, utils.RequestError{
				StatusCode: http.StatusBadRequest,
				Exception: exceptions.Exception{
					Message: "token not found",
					Code:    "AUTH_TOKEN_NOT_FOUND",
				},
			})
		}

		parts := strings.SplitN(token, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return utils.ResponseError(c, utils.RequestError{
				StatusCode: http.StatusBadRequest,
				Exception: exceptions.Exception{
					Message: "invalid Authorization header format",
					Code:    "AUTH_TOKEN_HEADER_INVALID",
				},
				Err: nil,
			})
		}

		user, err := md.GetUserByToken(c.Request().Context(), parts[1], userRepo)
		if err != nil {
			return utils.ResponseError(c, err)
		}

		for key, value := range user.AttributesPermitted {
			if key == route.Key && value == 1 {
				c.Set("user", user)
				return next(c)
			}
		}

		return utils.ResponseError(c, utils.RequestError{
			StatusCode: http.StatusUnauthorized,
			Exception: exceptions.Exception{
				Message: "user not authorized",
				Code:    "AUTH_USER_NOT_AUTHORIZED",
			},
			Err: nil,
		})
	}
}

func (md *AuthMiddleware) GetUserByToken(ctx context.Context, token string, userRepo repositories.UserRepositoryI) (dtos.UserDTO, error) {
	opts := facades.AuthCredentialsOptions{
		Realm:        md.auth.Keycloak.Admin.Realm,
		ClientID:     md.auth.Keycloak.Admin.ClientID,
		ClientSecret: md.auth.Keycloak.Admin.ClientSecret,
	}

	_, err := md.authFacade.CheckUserTokenIsValid(ctx, token, opts)
	if err != nil {
		return dtos.UserDTO{}, err
	}

	claims, err := md.authFacade.GetTokenClaims(ctx, token, opts)
	if err != nil {
		return dtos.UserDTO{}, err
	}

	userEmail := claims["email"].(string)

	user, err := userRepo.FindByEmail(ctx, userEmail)
	if err != nil {
		return dtos.UserDTO{}, err
	}

	userGroups, err := md.authFacade.GetUserGroups(ctx, facades.AuthGetUserGroupsOptions{
		UserID: user.ExternalId,
		AuthCredentialsOptions: facades.AuthCredentialsOptions{
			Realm:       md.auth.Keycloak.Admin.Realm,
			AccessToken: token,
		},
	})

	if err != nil {
		return dtos.UserDTO{}, err
	}

	user.AttributesPermitted = md.authFacade.GetPermittedAttributes(userGroups)
	return user, nil
}

func (md *AuthMiddleware) loadProvider(connectDB factories.Database) provider.RepositoriesProviderI {
	return &provider.RepositoriesProvider{
		Database: connectDB,
	}
}

func (md *AuthMiddleware) loginClient(ctx context.Context) (string, error) {
	token, err := md.authFacade.LoginAdmin(ctx, facades.AuthCredentialsOptions{
		Username: md.auth.Keycloak.Admin.AdminUser,
		Password: md.auth.Keycloak.Admin.AdminPassword,
		Realm:    md.auth.Keycloak.Admin.Realm,
	})
	if err != nil {
		return "", err
	}

	return token, nil
}
