package exceptions

var (
	ErrKeycloakClientLogin = Exception{
		Message: "error client login keycloak",
		Code:    "keycloak.login_client.error",
	}

	ErrKeycloakAdminLogin = Exception{
		Message: "error admin login keycloak",
		Code:    "keycloak.login_admin.error",
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
)
