package factories

import "github.com/labstack/echo/v4"

type RouteDriver string

const (
	ECHO_ROUTE_DRIVER = RouteDriver("echo")
)

type EchoRoutes struct {
	Client *echo.Echo
}

type Routes struct {
	Echo EchoRoutes
}

type RoutesConfig struct {
	Driver RouteDriver
}

func (cfg RoutesConfig) RoutesFactory() Routes {
	switch cfg.Driver {
	case ECHO_ROUTE_DRIVER:
		return cfg.NewEchoRoute()
	default:
		return Routes{}
	}
}

func (cfg RoutesConfig) NewEchoRoute() Routes {
	e := echo.New()

	return Routes{
		Echo: EchoRoutes{
			Client: e,
		},
	}
}
