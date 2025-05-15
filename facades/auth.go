package facades

import (
	"context"
	"errors"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/WV-Consultancy/snooker-pkg/exceptions"
	"github.com/WV-Consultancy/snooker-pkg/factories"
	"github.com/WV-Consultancy/snooker-pkg/utils"
)

type AuthFacadeInterface interface {
	CreateGroupInRealm(ctx context.Context, opts AuthCreateGroupOptions) (string, error)
	LoginClient(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	LoginAdmin(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	RegenerateClientSecret(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	RegisterUser(ctx context.Context, opts AuthRegisterUserOptions) (string, error)
	Login(ctx context.Context, opts AuthCredentialsOptions) (AuthTokens, error)
	JoinUserInGroup(ctx context.Context, opts AuthJoinUserGroup) error
	GetUserGroups(ctx context.Context, opts AuthGetUserGroupsOptions) ([]AuthUserGroup, error)
}

type AuthCreateGroupOptions struct {
	AccessToken string
	Realm       string
	GroupName   string
	Attributes  map[string][]string
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

type AuthJoinUserGroup struct {
	AuthCredentialsOptions
	UserID  string
	GroupID string
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

type AuthTokens struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  int
	RefreshExpiresIn int
}

type AuthGetUserGroupsOptions struct {
	AuthCredentialsOptions
	UserID string
}

type AuthUserGroup struct {
	ID         string
	Name       string
	Attributes map[string][]string
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

func (auth *AuthKeycloak) CreateGroupInRealm(ctx context.Context, opts AuthCreateGroupOptions) (string, error) {
	group := gocloak.Group{Name: gocloak.StringP(string(opts.GroupName)), Attributes: &opts.Attributes}

	groupId, err := auth.Keycloak.CreateGroup(ctx, opts.AccessToken, opts.Realm, group)
	if err != nil {
		auth.Logger.Error(exceptions.ErrCreateGroupInRealm.Message, Error(err))
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrCreateGroupInRealm,
			Err:        err,
		}
	}

	return groupId, nil
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

func (auth *AuthKeycloak) JoinUserInGroup(ctx context.Context, opts AuthJoinUserGroup) error {
	err := auth.Keycloak.AddUserToGroup(ctx, opts.AccessToken, opts.Realm, opts.UserID, opts.GroupID)
	if err != nil {
		return utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	return nil
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

func (auth *AuthKeycloak) Login(ctx context.Context, opts AuthCredentialsOptions) (AuthTokens, error) {
	if opts.Username == "" {
		return AuthTokens{}, errors.New("keycloak username is not defined")
	}

	if opts.Password == "" {
		return AuthTokens{}, errors.New("keycloak password is not defined")
	}

	if opts.Realm == "" {
		return AuthTokens{}, errors.New("realm is not defined")
	}

	token, err := auth.Keycloak.Login(ctx, opts.ClientID, opts.ClientSecret, opts.Realm, opts.Username, opts.Password)
	if err != nil {
		return AuthTokens{}, utils.RequestError{
			StatusCode: http.StatusUnauthorized,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	return AuthTokens{
		AccessToken:      token.AccessToken,
		RefreshToken:     token.RefreshToken,
		AccessExpiresIn:  token.ExpiresIn,
		RefreshExpiresIn: token.RefreshExpiresIn,
	}, nil
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

func (auth *AuthKeycloak) GetUserGroups(ctx context.Context, opts AuthGetUserGroupsOptions) ([]AuthUserGroup, error) {
	var groupsRes []AuthUserGroup

	groups, err := auth.Keycloak.GetUserGroups(ctx, opts.AccessToken, opts.Realm, opts.UserID, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	for _, group := range groups {
		g := AuthUserGroup{
			ID:         *group.ID,
			Name:       *group.Name,
			Attributes: *group.Attributes,
		}

		groupsRes = append(groupsRes, g)
	}
	return groupsRes, nil
}
