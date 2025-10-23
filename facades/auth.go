package facades

import (
	"context"
	"fmt"
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
	GetPermittedAttributes(groups []AuthUserGroup, attrsPermitted map[string]int)
	LogoutAllSessionUser(ctx context.Context, userId string, opts AuthCredentialsOptions) error
	RefreshUserToken(ctx context.Context, refreshToken string, opts AuthCredentialsOptions) (AuthTokens, error)
	GetSubgroups(ctx context.Context, groupUUID string, opts AuthCredentialsOptions) ([]AuthUserGroup, error)
	GetGroup(ctx context.Context, groupUUID string, opts AuthCredentialsOptions) (AuthUserGroup, error)
	DeleteGroup(ctx context.Context, groupUUID string, opts AuthCredentialsOptions) error
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
	Config   factories.AuthConfig
}

func NewAuthFacade(auth factories.Auth, logger LoggerFacadeInterface, config factories.AuthConfig) AuthFacadeInterface {
	return &AuthKeycloak{
		Keycloak: auth.Keycloak.Client,
		Config:   config,
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

func (auth *AuthKeycloak) GetGroup(ctx context.Context, groupUUID string, opts AuthCredentialsOptions) (AuthUserGroup, error) {
	group, err := auth.Keycloak.GetGroup(ctx, opts.AccessToken, opts.Realm, groupUUID)
	if err != nil {
		auth.Logger.Error("error find group", Error(err))
		return AuthUserGroup{}, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrGetGroup,
			Err:        err,
		}
	}

	groupF := AuthUserGroup{
		ID:         group.ID,
		Name:       group.Name,
		Attributes: map[string]int{},
	}

	groupF.Attributes, err = auth.processAttributes(group.Attributes)
	if err != nil {
		return AuthUserGroup{}, err
	}

	return groupF, nil
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

	groupsFormat, err := auth.proccessGroups(ctx, groups, opts.AuthCredentialsOptions)
	if err != nil {
		auth.Logger.Info("error proccess keycloak groups", Error(err))
		return nil, err
	}

	auth.Logger.Info("groups format", Any("groups", groupsFormat))
	return groupsFormat, nil
}

func (auth *AuthKeycloak) GetSubgroups(ctx context.Context, groupUUID string, opts AuthCredentialsOptions) ([]AuthUserGroup, error) {
	path := fmt.Sprintf("%s/admin/realms/%s/groups/%s/children", auth.Config.Keycloak.URL, opts.Realm, groupUUID)
	auth.Logger.Info("request subgroups", String("path", path))
	subgroups := []gocloak.Group{}
	resp, err := auth.Keycloak.GetRequestWithBearerAuth(ctx, opts.AccessToken).
		SetAuthToken(opts.AccessToken).
		SetResult(&subgroups).
		Get(path)
	if err != nil || resp == nil || resp.IsError() {
		auth.Logger.Error("error find group in keycloak", Error(err))
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrKeycloakGetGroup,
			Err:        err,
		}
	}

	auth.Logger.Info("subgroups by keycloak", Any("subgroups", subgroups))
	if subgroups == nil && len(subgroups) <= 0 {
		auth.Logger.Error("subgroups not found", String("group_id", groupUUID))
		return nil, utils.RequestError{
			StatusCode: http.StatusNoContent,
			Exception: exceptions.Exception{
				Message: "subgroups not found",
				Code:    exceptions.AuthSubGroupsNotFound,
			},
		}
	}

	res := []AuthUserGroup{}
	for _, group := range subgroups {
		fGroup := AuthUserGroup{
			ID:         group.ID,
			Name:       group.Name,
			Attributes: map[string]int{},
		}

		fGroup.Attributes, err = auth.processAttributes(group.Attributes)
		if err != nil {
			return nil, err
		}

		subs, err := auth.GetSubgroups(ctx, *group.ID, opts)
		if err != nil {
			return nil, err
		}

		if len(subs) > 0 {
			fGroup.Childrens = subs
		}

		res = append(res, fGroup)
	}

	return res, nil
}

func (auth *AuthKeycloak) DeleteGroup(ctx context.Context, groupUUID string, opts AuthCredentialsOptions) error {
	err := auth.Keycloak.DeleteGroup(ctx, opts.AccessToken, opts.Realm, groupUUID)
	if err != nil {
		return utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception: exceptions.Exception{
				Message: "error delete group",
				Code:    exceptions.KCAdminDeleteGroupError,
			},
		}
	}

	return nil
}

func (auth *AuthKeycloak) UpdateGroup(ctx context.Context, group AuthUserGroup, opts AuthCredentialsOptions) error {
	attrs := map[string][]string{}

	for key, value := range group.Attributes {
		attrs[key] = []string{strconv.Itoa(value)}
	}

	err := auth.Keycloak.UpdateGroup(ctx, opts.AccessToken, opts.Realm, gocloak.Group{
		ID:         group.ID,
		Name:       group.Name,
		Attributes: &attrs,
	})

	if err != nil {
		auth.Logger.Error(exceptions.ErrUpdateGroup.Message, Error(err))
		return utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrUpdateGroup,
			Err:        err,
		}
	}

	return nil
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
		auth.Logger.Error(exceptions.ErrClaimsIsEmpty.Message, Error(err))
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrDecodeAccessToken,
			Err:        err,
		}
	}

	if claims == nil {
		auth.Logger.Error(exceptions.ErrClaimsIsEmpty.Message)
		return nil, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrClaimsIsEmpty,
			Err:        nil,
		}
	}

	return *claims, nil
}

func (auth *AuthKeycloak) GetPermittedAttributes(groups []AuthUserGroup, attrsPermitted map[string]int) {
	auth.Logger.Info("auth user groups", Any("groups", groups))
	for _, group := range groups {
		for key, value := range group.Attributes {
			auth.Logger.Info("group attrs", Any("attrs", group.Attributes))
			attrValue, ok := attrsPermitted[key]
			if !ok {
				attrsPermitted[key] = value
			}

			if ok && (attrValue == value) {
				attrsPermitted[key] = value
			}
		}

		if len(group.Childrens) > 0 {
			auth.GetPermittedAttributes(group.Childrens, attrsPermitted)
		}
	}

	auth.Logger.Info("attrs permitted", Any("attrs", attrsPermitted))
}

func (auth *AuthKeycloak) LogoutAllSessionUser(ctx context.Context, userId string, opts AuthCredentialsOptions) error {
	err := auth.Keycloak.LogoutAllSessions(ctx, opts.AccessToken, opts.Realm, userId)
	if err != nil {
		auth.Logger.Error(exceptions.ErrLogoutAllSessions.Message, Error(err))
		return utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.ErrLogoutAllSessions,
			Err:        err,
		}
	}

	return nil
}

func (auth *AuthKeycloak) RefreshUserToken(ctx context.Context, refreshToken string, opts AuthCredentialsOptions) (AuthTokens, error) {
	token, err := auth.Keycloak.RefreshToken(ctx, refreshToken, opts.ClientID, opts.ClientSecret, opts.Realm)
	if err != nil {
		auth.Logger.Error("refresh token error", Error(err))
		return AuthTokens{}, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
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

func (auth *AuthKeycloak) proccessGroups(ctx context.Context, groups []*gocloak.Group, opts AuthCredentialsOptions) ([]AuthUserGroup, error) {
	var groupsRes []AuthUserGroup
	groupsId := map[string]bool{}
	var err error

	for _, group := range groups {
		groupsId[*group.ID] = true
	}

	auth.Logger.Info("process groups", Any("groups", groups))
	for _, group := range groups {
		exist := auth.groupExistInSubgroup(*group.ID, groupsRes)
		if exist {
			continue
		}

		if group.ID == nil {
			continue
		}

		g := AuthUserGroup{
			ID:         group.ID,
			Name:       group.Name,
			Attributes: map[string]int{},
		}

		g.Attributes, err = auth.processAttributes(group.Attributes)
		if err != nil {
			return nil, err
		}

		subgroups, err := auth.GetSubgroups(ctx, *group.ID, opts)
		if err != nil {
			return nil, err
		}

		g.Childrens = subgroups
		groupsRes = append(groupsRes, g)
	}

	return groupsRes, nil
}
func (auth *AuthKeycloak) groupExistInSubgroup(groupId string, groups []AuthUserGroup) bool {
	for _, group := range groups {
		if *group.ID == groupId {
			return true
		}

		if len(group.Childrens) > 0 {
			exist := auth.groupExistInSubgroup(groupId, group.Childrens)

			if exist {
				return exist
			}
		}
	}

	return false
}

func (auth *AuthKeycloak) processAttributes(attributes *map[string][]string) (map[string]int, error) {
	attrs := map[string]int{}
	if attributes != nil {
		for key, value := range *attributes {
			if len(value) == 0 {
				continue
			}

			v, err := strconv.Atoi(value[0])
			if err != nil {
				auth.Logger.Error("error format attribute value", Error(err))
				return nil, utils.RequestError{
					StatusCode: http.StatusInternalServerError,
					Exception: exceptions.Exception{
						Message: "error format attributes",
						Code:    "AUTH_FORMAT_ATTRIBUTES_ERROR",
					},
					Err: err,
				}
			}
			attrs[key] = v
		}
	}

	return attrs, nil
}
