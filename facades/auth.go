package facades

import (
	"context"
	"net/http"
	"strconv"

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
	GetTokenClaims(ctx context.Context, token string, opts AuthCredentialsOptions) (map[string]interface{}, error)
	GetPermittedAttributes(groups []AuthUserGroup) map[string]int
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
	ID         *string
	Name       *string
	Attributes map[string]int
	Childrens  []AuthUserGroup
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
		auth.Logger.Error(exceptions.ErrKeycloakCreateGroup.Message, Error(err))
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
		auth.Logger.Error(exceptions.ErrKeycloakCreateGroup.Message, Error(err))
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
		auth.Logger.Error(exceptions.ErrKeycloakCreateUser.Message, Error(err))
		return "", utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakCreateUser,
			Err:        err,
		}
	}

	err = auth.Keycloak.SetPassword(ctx, opts.AccessToken, userID, opts.Realm, opts.User.Password, false)
	if err != nil {
		auth.Logger.Error("set password in keycloak error", Error(err))
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
		auth.Logger.Error(exceptions.ErrKeycloakJoinUserToGroup.Message, Error(err))
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
		auth.Logger.Error(exceptions.ErrKeycloakRemoveUserToGroup.Message, Error(err))
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
		auth.Logger.Error("client id not defined")
		return "", utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakClientIDNotDefined,
			Err:        nil,
		}
	}

	if opts.ClientSecret == "" {
		auth.Logger.Error("client secret not defined")
		return "", utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakClientSecretNotDefined,
			Err:        nil,
		}
	}

	if opts.Realm == "" {
		auth.Logger.Error("realm not defined")
		return "", utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakRealmNotDefined,
			Err:        nil,
		}
	}

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
		auth.Logger.Error(exceptions.ErrKeycloakAdminUsernameNotDefined.Message)
		return "", &utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakAdminUsernameNotDefined,
			Err:        nil,
		}
	}

	if opts.Password == "" {
		auth.Logger.Error(exceptions.ErrKeycloakAdminPassowordNotDefined.Message)
		return "", &utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakAdminPassowordNotDefined,
			Err:        nil,
		}
	}

	if opts.Realm == "" {
		auth.Logger.Error(exceptions.ErrKeycloakRealmNotDefined.Message)
		return "", &utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakRealmNotDefined,
			Err:        nil,
		}
	}

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
		return AuthTokens{}, utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakAdminUsernameNotDefined,
		}
	}

	if opts.Password == "" {
		return AuthTokens{}, utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakAdminPassowordNotDefined,
		}
	}

	if opts.Realm == "" {
		return AuthTokens{}, utils.RequestError{
			StatusCode: http.StatusBadRequest,
			Exception:  exceptions.ErrKeycloakRealmNotDefined,
		}
	}

	token, err := auth.Keycloak.Login(ctx, opts.ClientID, opts.ClientSecret, opts.Realm, opts.Username, opts.Password)
	if err != nil {
		auth.Logger.Error(exceptions.ErrKeycloakLogin.Message, Error(err))
		return AuthTokens{}, utils.RequestError{
			StatusCode: http.StatusUnauthorized,
			Exception:  exceptions.ErrKeycloakLogin,
			Err:        err,
		}
	}

	auth.Logger.Info("keycloak login successfuly")
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
		auth.Logger.Error(exceptions.ErrRegenerateSecrete.Message, Error(err))
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
		auth.Logger.Error(exceptions.ErrKeycloakGetUserGroups.Message, Error(err))
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakGetUserGroups,
			Err:        err,
		}
	}

	groupsFormat, err := auth.proccessGroups(ctx, groups, opts)
	if err != nil {
		auth.Logger.Info("proccess keycloak groups", Any("groups", groups))
		return nil, err
	}

	return groupsFormat, nil
}

func (auth *AuthKeycloak) CheckUserTokenIsValid(ctx context.Context, token string, opts AuthCredentialsOptions) (bool, error) {
	res, err := auth.Keycloak.RetrospectToken(ctx, token, opts.ClientID, opts.ClientSecret, opts.Realm)
	if err != nil {
		auth.Logger.Error(exceptions.ErrCheckAccessToken.Message, Error(err))
		return false, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrCheckAccessToken,
			Err:        err,
		}
	}

	if res.Active != nil && !*res.Active {
		auth.Logger.Error(exceptions.ErrAccessTokenInative.Message)
		return false, utils.RequestError{
			StatusCode: http.StatusUnauthorized,
			Exception:  exceptions.ErrAccessTokenInative,
			Err:        nil,
		}
	}

	return true, nil
}

func (auth *AuthKeycloak) GetTokenClaims(ctx context.Context, token string, opts AuthCredentialsOptions) (map[string]interface{}, error) {
	_, claims, err := auth.Keycloak.DecodeAccessToken(ctx, token, opts.Realm)
	if err != nil {
		auth.Logger.Error(exceptions.ErrAccessTokenInative.Message, Error(err))
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrDecodeAccessToken,
			Err:        err,
		}
	}

	if claims == nil {
		auth.Logger.Error(exceptions.ErrAccessTokenInative.Message)
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrClaimsIsEmpty,
			Err:        nil,
		}
	}

	return *claims, nil
}

func (auth *AuthKeycloak) GetPermittedAttributes(groups []AuthUserGroup) map[string]int {
	attrsPermitted := map[string]int{}

	for _, group := range groups {
		for key, value := range group.Attributes {
			attrValue, ok := attrsPermitted[key]
			if !ok {
				attrsPermitted[key] = value
			}

			if ok && (attrValue == value) {
				attrsPermitted[key] = value
			}
		}
	}

	return attrsPermitted
}

func (auth *AuthKeycloak) proccessGroups(ctx context.Context, groups []*gocloak.Group, opts AuthGetUserGroupsOptions) ([]AuthUserGroup, error) {
	var groupsRes []AuthUserGroup

	for _, group := range groups {
		if group.ID == nil {
			auth.Logger.Info("group ID not defined. Ignore group in proccess.", Any("group", group))
			continue
		}

		fullGroup, err := auth.Keycloak.GetGroup(ctx, opts.AccessToken, opts.Realm, *group.ID)
		if err != nil {
			auth.Logger.Error(exceptions.ErrKeycloakGetGroup.Message, Any("group_id", *group.ID), Error(err))
			return nil, utils.RequestError{
				StatusCode: http.StatusInternalServerError,
				Exception:  exceptions.ErrKeycloakGetGroup,
				Err:        err,
			}
		}

		g := AuthUserGroup{
			ID:         fullGroup.ID,
			Name:       fullGroup.Name,
			Attributes: map[string]int{},
		}

		if fullGroup.Attributes != nil {
			for key, value := range *fullGroup.Attributes {
				if len(value) == 0 {
					continue
				}
				v, err := strconv.Atoi(value[0])
				if err != nil {
					auth.Logger.Error("atributo não numérico", Error(err))
					continue
				}
				g.Attributes[key] = v
			}
		}

		if fullGroup.SubGroups != nil && len(*fullGroup.SubGroups) > 0 {
			auth.Logger.Debug("proccess subgroups", Any("group_id", fullGroup.ID))
			subGroupsPtr := make([]*gocloak.Group, 0, len(*fullGroup.SubGroups))
			for i := range *fullGroup.SubGroups {
				subGroupsPtr = append(subGroupsPtr, &(*fullGroup.SubGroups)[i])
			}

			subgroups, err := auth.proccessGroups(ctx, subGroupsPtr, opts)
			if err != nil {
				auth.Logger.Error(exceptions.ErrProccessSubGroups.Message, Error(err))
				return nil, utils.RequestError{
					StatusCode: http.StatusInternalServerError,
					Exception:  exceptions.ErrProccessSubGroups,
					Err:        err,
				}
			}
			g.Childrens = subgroups
		}

		groupsRes = append(groupsRes, g)
	}

	return groupsRes, nil
}
