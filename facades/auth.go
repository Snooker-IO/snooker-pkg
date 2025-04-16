package facades

import (
	"context"
	"errors"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/WV-Consultancy/pkg/exceptions"
	"github.com/WV-Consultancy/pkg/factories"
	"github.com/WV-Consultancy/pkg/utils"
)

type AuthFacadeInterface interface {
	RegisterRealm(ctx context.Context, opts AuthRegisterRealmOptions) error
	AddGroupsInRealm(ctx context.Context, opts AuthAddGroupsInRealmOptions) error
	CreateRealmRoles(ctx context.Context, opts AuthCreateRealmRolesOptions) ([]string, error)
	LoginClient(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	LoginAdmin(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	RegenerateClientSecret(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	RegisterUser(ctx context.Context, opts AuthRegisterUserOptions) (string, error)
}

type AuthCredentialsOptions struct {
	ClientID     string
	ClientSecret string
	Realm        string
	Username     string
	Password     string
	AccessToken  string
}

type AuthRegisterRealmOptions struct {
	AuthCredentialsOptions
}

type AuthRegisterUserOptions struct {
	AuthCredentialsOptions
	User   AuthUser
	Groups []string
}

type AuthCreateRealmRolesOptions struct {
	AuthCredentialsOptions
	Roles []RealmRole
}

type AuthAddGroupsInRealmOptions struct {
	AuthCredentialsOptions
	RolesName []string
	Groups    []string
}

type AuthUser struct {
	Username      string
	Email         string
	Password      string
	Enable        bool
	EmailVerified bool
}

type RealmRole struct {
	Name        string
	Description string
}

type AuthKeycloak struct {
	Logger   LoggerFacadeInterface
	Keycloak *gocloak.GoCloak
}

func NewAuthFacade(auth factories.Auth, logger LoggerFacadeInterface) AuthFacadeInterface {
	return &AuthKeycloak{
		Keycloak: auth.Keycloak.Client,
		Logger:   logger,
	}
}

func (auth *AuthKeycloak) RegisterRealm(ctx context.Context, opts AuthRegisterRealmOptions) (err error) {
	realmRep := gocloak.RealmRepresentation{
		Realm:   gocloak.StringP(opts.Realm),
		Enabled: gocloak.BoolP(true),
	}

	_, err = auth.Keycloak.CreateRealm(ctx, opts.AccessToken, realmRep)
	if err != nil {
		return utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrCreateRealm,
			Err:        err,
		}
	}

	return nil
}

func (auth *AuthKeycloak) AddGroupsInRealm(ctx context.Context, opts AuthAddGroupsInRealmOptions) error {
	var apiErr gocloak.APIError
	var realmRoles []gocloak.Role

	roles, err := auth.Keycloak.GetRealmRoles(ctx, opts.AccessToken, opts.Realm, gocloak.GetRoleParams{})
	if err != nil {
		errors.As(err, &apiErr)
		return utils.RequestError{
			StatusCode: apiErr.Code,
			Exception:  exceptions.ErrGetRoles,
			Err:        err,
		}
	}

	for _, role := range roles {
		for _, roleName := range opts.RolesName {
			if *role.Name == roleName {
				realmRoles = append(realmRoles, *role)
			}
		}
	}

	auth.Logger.Info("realm roles", Any("roles", realmRoles))
	for _, groupName := range opts.Groups {
		group := gocloak.Group{Name: gocloak.StringP(string(groupName))}
		groupId, err := auth.Keycloak.CreateGroup(ctx, opts.AccessToken, opts.Realm, group)
		errors.As(err, &apiErr)
		if err != nil {
			return utils.RequestError{
				StatusCode: apiErr.Code,
				Exception:  exceptions.ErrCreateRealmGroups,
				Err:        err,
			}
		}

		err = auth.Keycloak.AddRealmRoleToGroup(ctx, opts.AccessToken, opts.Realm, groupId, realmRoles)
		errors.As(err, &apiErr)
		if err != nil {
			return utils.RequestError{
				StatusCode: apiErr.Code,
				Exception:  exceptions.ErrLinkRoleToGroup,
				Err:        err,
			}
		}
	}

	return nil
}

func (auth *AuthKeycloak) CreateRealmRoles(ctx context.Context, opts AuthCreateRealmRolesOptions) ([]string, error) {
	var rolesRes []string
	for _, permission := range opts.Roles {
		role := gocloak.Role{
			Name:        gocloak.StringP(permission.Name),
			Description: gocloak.StringP(permission.Description),
		}

		roleUUID, err := auth.Keycloak.CreateRealmRole(ctx, opts.AccessToken, opts.Realm, role)
		if err != nil {
			return nil, utils.RequestError{}
		}

		rolesRes = append(rolesRes, roleUUID)
	}

	return rolesRes, nil
}

func (auth *AuthKeycloak) RegisterUser(ctx context.Context, opts AuthRegisterUserOptions) (string, error) {
	userRegister := gocloak.User{
		Username:      gocloak.StringP(opts.User.Username),
		Email:         gocloak.StringP(opts.User.Email),
		Enabled:       gocloak.BoolP(opts.User.Enable),
		EmailVerified: gocloak.BoolP(opts.User.EmailVerified),
		Groups:        &opts.Groups,
	}

	userID, err := auth.Keycloak.CreateUser(ctx, opts.AccessToken, opts.Realm, userRegister)
	if err != nil {
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	err = auth.Keycloak.SetPassword(ctx, opts.AccessToken, userID, opts.Realm, opts.User.Password, false)
	if err != nil {
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	return userID, nil
}

func (auth *AuthKeycloak) LoginClient(ctx context.Context, opts AuthCredentialsOptions) (string, error) {
	if opts.ClientID == "" {
		return "", errors.New("client id is not defined")
	}

	if opts.ClientSecret == "" {
		return "", errors.New("client secret is not defined")
	}

	if opts.Realm == "" {
		return "", errors.New("realm is not defined")
	}

	auth.Logger.Info("keycloack login client", Any("keys", opts))

	token, err := auth.Keycloak.LoginClient(ctx, opts.ClientID, opts.ClientSecret, opts.Realm)
	if err != nil {
		auth.Logger.Error("error keycloak login client", Error(err))
		return "", utils.RequestError{
			StatusCode: http.StatusUnauthorized,
			Exception:  exceptions.ErrKeycloakClientLogin,
			Err:        err,
		}
	}

	auth.Logger.Info("keycloak login client successfuly")
	return token.AccessToken, nil
}

func (auth *AuthKeycloak) LoginAdmin(ctx context.Context, opts AuthCredentialsOptions) (string, error) {
	if opts.Username == "" {
		return "", errors.New("keycloak username is not defined")
	}

	if opts.Password == "" {
		return "", errors.New("keycloak password is not defined")
	}

	if opts.Realm == "" {
		return "", errors.New("realm is not defined")
	}

	auth.Logger.Info("keycloack login admin", Any("keys", opts))

	token, err := auth.Keycloak.LoginAdmin(ctx, opts.Username, opts.Password, opts.Realm)
	if err != nil {
		auth.Logger.Error("error keycloak admin", Error(err))
		return "", utils.RequestError{
			StatusCode: http.StatusUnauthorized,
			Exception:  exceptions.ErrKeycloakAdminLogin,
			Err:        err,
		}
	}

	auth.Logger.Info("keycloak login admin successfuly")
	return token.AccessToken, nil
}

func (auth *AuthKeycloak) RegenerateClientSecret(ctx context.Context, opts AuthCredentialsOptions) (string, error) {
	credentials, err := auth.Keycloak.RegenerateClientSecret(ctx, opts.AccessToken, opts.Realm, opts.ClientID)
	if err != nil {
		auth.Logger.Error("error regenerate client secret", Error(err))
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrRegenerateSecrete,
			Err:        err,
		}
	}

	return *credentials.SecretData, nil
}
