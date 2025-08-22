package exceptions

import "fmt"

var (
	ErrKeycloakClientLogin = Exception{
		Message: "keycloak client login error",
		Code:    "keycloak.login_client.error",
	}

	ErrKeycloakClientIDNotDefined = Exception{
		Message: "keycloak client id is not defined",
		Code:    "keycloak.login_client.client_id_not_defined.error",
	}

	ErrKeycloakClientSecretNotDefined = Exception{
		Message: "keycloak client secret is not defined",
		Code:    "keycloak.login_client.client_secret_not_defined.error",
	}

	ErrKeycloakAdminUsernameNotDefined = Exception{
		Message: "keycloak admin username is not defined",
		Code:    "keycloak.login_admin.username_not_defined.error",
	}

	ErrKeycloakAdminPassowordNotDefined = Exception{
		Message: "keycloak admin password is not defined",
		Code:    "keycloak.login_admin.password_not_defined.error",
	}

	ErrKeycloakRealmNotDefined = func(funcName string) Exception {
		return Exception{
			Message: "keycloak realm is not defined",
			Code:    fmt.Sprintf("keycloak.%s.realm_not_defined.error", funcName),
		}
	}

	ErrKeycloakAdminLogin = Exception{
		Message: "keycloak admin login error",
		Code:    "keycloak.login_admin.error",
	}

	ErrKeycloakCreateUser = Exception{
		Message: "keycloak create user error",
		Code:    "keycloak.create_user.error",
	}

	ErrKeycloakSetPassword = Exception{
		Message: "keycloak user set password error",
		Code:    "keycloak.create_user.set_password.error",
	}

	ErrCreateRealm = Exception{
		Message: "error create organization realm",
		Code:    "keycloak.create_r.error",
	}

	ErrCreateRealmGroups = Exception{
		Message: "error create realm groups",
		Code:    "keycloak.create_group.error",
	}

	ErrRegenerateSecrete = Exception{
		Message: "error regenerate realm client secret",
		Code:    "keycloak.regenerate_secret.error",
	}

	ErrLinkRoleToGroup = Exception{
		Message: "error link realm role to group",
		Code:    "keycloak.add_roles_group.error",
	}

	ErrGetRoles = Exception{
		Message: "error get realm roles",
		Code:    "keycloak.get_roles.error",
	}

	ErrKeycloakCreateGroup = Exception{
		Message: "keycloak create group in realm error",
		Code:    "keycloak.create_group.error",
	}

	ErrKeycloakJoinUserToGroup = Exception{
		Message: "keycloak add user in group error",
		Code:    "keycloak.join_group_to_user.error",
	}

	ErrKeycloakRemoveUserToGroup = Exception{
		Message: "keycloak remove user from group error",
		Code:    "keycloak.remove_user_to_group.error",
	}
)
