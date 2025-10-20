package exceptions

const (
	KCRealmNotDefined             = "KEYCLOAK_REALM_NOT_DEFINED"
	KCAdminLoginError             = "KEYCLOAK_ADMIN_LOGIN_ERROR"
	KCLoginError                  = "KEYCLOAK_LOGIN_ERROR"
	KCAdminCreateUserError        = "KEYCLOAK_ADMIN_CREATE_USER_ERROR"
	KCAdminUserSetPasswordError   = "KEYCLOAK_ADMIN_USER_SET_PASSWORD_ERROR"
	KCRegenerateClientSecretError = "KEYCLOAK_REGENERATE_CLIENT_SECRET_ERROR"

	KCAdminCreateGroupError     = "KEYCLOAK_ADMIN_CREATE_GROUP_ERROR"
	KCAdminAddUserGroupError    = "KEYCLOAK_ADMIN_ADD_USER_GROUP_ERROR"
	KCAdminRemoveUserGroupError = "KEYCLOAK_ADMIN_REMOVE_USER_GROUP_ERROR"
	KCAdminGetUserGroupsError   = "KEYCLOAK_ADMIN_GET_USER_GROUPS_ERROR"
	KCAdminGetGroupError        = "KEYCLOAK_ADMIN_GET_GROUP_ERROR"

	KCLoginClientError        = "KEYCLOAK_LOGIN_CLIENT_ERROR"
	KCCLientIdNotDefined      = "KEYCLOAK_CLIENT_ID_NOT_DEFINED"
	KCClientSecretNotDefined  = "KEYCLOAK_CLIENT_SECRET_NOT_DEFINED"
	KCAdminUsernameNotDefined = "KEYCLOAK_ADMIN_USERNAME_NOT_DEFINED"
	KCAdminPasswordNotDefined = "KEYCLOAK_ADMIN_PASSWORD_NOT_DEFINED"

	AuthProccessSubgroupError = "AUTH_PROCCESS_SUBGROUP_ERROR"
)

var (
	ErrKeycloakClientLogin = Exception{
		Message: "keycloak client login error",
		Code:    KCLoginClientError,
	}

	ErrKeycloakClientIDNotDefined = Exception{
		Message: "keycloak client id is not defined",
		Code:    KCCLientIdNotDefined,
	}

	ErrKeycloakClientSecretNotDefined = Exception{
		Message: "keycloak client secret is not defined",
		Code:    KCClientSecretNotDefined,
	}

	ErrKeycloakAdminUsernameNotDefined = Exception{
		Message: "keycloak admin username is not defined",
		Code:    KCAdminUsernameNotDefined,
	}

	ErrKeycloakAdminPassowordNotDefined = Exception{
		Message: "keycloak admin password is not defined",
		Code:    KCAdminPasswordNotDefined,
	}

	ErrKeycloakRealmNotDefined = Exception{
		Message: "keycloak realm is not defined",
		Code:    KCRealmNotDefined,
	}

	ErrKeycloakAdminLogin = Exception{
		Message: "keycloak admin login error",
		Code:    KCAdminLoginError,
	}

	ErrKeycloakLogin = Exception{
		Message: "keycloak login error",
		Code:    KCLoginError,
	}

	ErrKeycloakCreateUser = Exception{
		Message: "keycloak create user error",
		Code:    KCAdminCreateUserError,
	}

	ErrKeycloakSetPassword = Exception{
		Message: "keycloak user set password error",
		Code:    KCAdminUserSetPasswordError,
	}

	ErrKeycloakCreateGroup = Exception{
		Message: "error create group",
		Code:    KCAdminCreateGroupError,
	}

	ErrKeycloakGetUserGroups = Exception{
		Message: "error get user groups",
		Code:    KCAdminGetUserGroupsError,
	}

	ErrKeycloakGetGroup = Exception{
		Message: "error get group",
		Code:    KCAdminGetGroupError,
	}

	ErrKeycloakJoinUserToGroup = Exception{
		Message: "keycloak add user in group error",
		Code:    KCAdminAddUserGroupError,
	}

	ErrKeycloakRemoveUserToGroup = Exception{
		Message: "keycloak remove user from group error",
		Code:    KCAdminRemoveUserGroupError,
	}

	ErrRegenerateSecrete = Exception{
		Message: "error regenerate realm client secret",
		Code:    KCRegenerateClientSecretError,
	}

	ErrProccessSubGroups = Exception{
		Message: "error proccess subgroups",
		Code:    AuthProccessSubgroupError,
	}
)
