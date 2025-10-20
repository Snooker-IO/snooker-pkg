package facades

import (
	"context"
	"errors"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/Snooker-IO/snooker-pkg/exceptions"
	"github.com/Snooker-IO/snooker-pkg/factories"
	"github.com/Snooker-IO/snooker-pkg/utils"
)

type AuthFacadeInterface interface {
	CreateGroup(ctx context.Context, groupName string, opts AuthCreateGroupOptions) (string, error)
	CreateChildGroup(ctx context.Context, groupName string, mainGroupId string, opts AuthCreateGroupOptions) (string, error)
	LoginClient(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	LoginAdmin(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	RegenerateClientSecret(ctx context.Context, opts AuthCredentialsOptions) (string, error)
	CreateUser(ctx context.Context, opts AuthCreateUserOptions) (string, error)
	Login(ctx context.Context, opts AuthCredentialsOptions) (AuthTokens, error)
	JoinUserToGroup(ctx context.Context, opts AuthJoinUserGroup) error
	RemoveUserToGroup(ctx context.Context, opts AuthJoinUserGroup) error
	GetUserGroups(ctx context.Context, opts AuthGetUserGroupsOptions) ([]AuthUserGroup, error)
	CheckUserTokenIsValid(ctx context.Context, token string, opts AuthCredentialsOptions) (bool, error)
}

type AuthCreateGroupOptions struct {
	AccessToken string
	Realm       string
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

type AuthCreateUserOptions struct {
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

func (auth *AuthKeycloak) CreateGroup(ctx context.Context, groupName string, opts AuthCreateGroupOptions) (string, error) {
	group := gocloak.Group{
		Name:       gocloak.StringP(groupName),
		Attributes: &opts.Attributes,
	}

	groupId, err := auth.Keycloak.CreateGroup(ctx, opts.AccessToken, opts.Realm, group)
	if err != nil {
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakCreateGroup,
			Err:        err,
		}
	}

	return groupId, nil
}

func (auth *AuthKeycloak) CreateChildGroup(ctx context.Context, groupName string, mainGroupId string, opts AuthCreateGroupOptions) (string, error) {
	group := gocloak.Group{
		Name:       gocloak.StringP(groupName),
		Attributes: &opts.Attributes,
	}

	groupId, err := auth.Keycloak.CreateChildGroup(ctx, opts.AccessToken, opts.Realm, mainGroupId, group)
	if err != nil {
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakCreateGroup,
			Err:        err,
		}
	}

	return groupId, nil
}

func (auth *AuthKeycloak) CreateUser(ctx context.Context, opts AuthCreateUserOptions) (string, error) {
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
			Exception:  exceptions.ErrKeycloakCreateUser,
			Err:        err,
		}
	}

	err = auth.Keycloak.SetPassword(ctx, opts.AccessToken, userID, opts.Realm, opts.User.Password, false)
	if err != nil {
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakSetPassword,
			Err:        err,
		}
	}

	return userID, nil
}

func (auth *AuthKeycloak) JoinUserToGroup(ctx context.Context, opts AuthJoinUserGroup) error {
	err := auth.Keycloak.AddUserToGroup(ctx, opts.AccessToken, opts.Realm, opts.UserID, opts.GroupID)
	if err != nil {
		return utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakJoinUserToGroup,
			Err:        err,
		}
	}

	return nil
}

func (auth *AuthKeycloak) RemoveUserToGroup(ctx context.Context, opts AuthJoinUserGroup) error {
	err := auth.Keycloak.DeleteUserFromGroup(ctx, opts.AccessToken, opts.Realm, opts.UserID, opts.GroupID)
	if err != nil {
		return utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakRemoveUserToGroup,
			Err:        err,
		}
	}

	return nil
}

func (auth *AuthKeycloak) LoginClient(ctx context.Context, opts AuthCredentialsOptions) (string, error) {
	if opts.ClientID == "" {
		return "", utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakClientIDNotDefined,
			Err:        nil,
		}
	}

	if opts.ClientSecret == "" {
		return "", utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakClientSecretNotDefined,
			Err:        nil,
		}
	}

	if opts.Realm == "" {
		return "", utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakRealmNotDefined("login_client"),
			Err:        nil,
		}
	}

	auth.Logger.Info("keycloack login client", Any("keys", opts))

	token, err := auth.Keycloak.LoginClient(ctx, opts.ClientID, opts.ClientSecret, opts.Realm)
	if err != nil {
		auth.Logger.Error(exceptions.ErrKeycloakClientLogin.Message, Error(err))
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
		return "", &utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakAdminUsernameNotDefined,
			Err:        nil,
		}
	}

	if opts.Password == "" {
		return "", &utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakAdminPassowordNotDefined,
			Err:        nil,
		}
	}

	if opts.Realm == "" {
		return "", &utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakRealmNotDefined("login_admin"),
			Err:        nil,
		}
	}

	auth.Logger.Info("keycloack login admin", Any("keys", opts))

	token, err := auth.Keycloak.LoginAdmin(ctx, opts.Username, opts.Password, opts.Realm)
	if err != nil {
		auth.Logger.Error(exceptions.ErrKeycloakAdminLogin.Message, Error(err))
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

	groups, err := auth.Keycloak.GetUserGroups(ctx, opts.AccessToken, opts.Realm, opts.UserID, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	groupsRes := make([]AuthUserGroup, len(groups))
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

func (auth *AuthKeycloak) CheckUserTokenIsValid(ctx context.Context, token string, opts AuthCredentialsOptions) (bool, error) {
	res, err := auth.Keycloak.RetrospectToken(ctx, token, opts.ClientID, opts.ClientSecret, opts.Realm)
	if err != nil {
		return false, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	if res.Active != nil && !*res.Active {
		return false, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        errors.New("invalid user token"),
		}
	}

	return true, nil
}
