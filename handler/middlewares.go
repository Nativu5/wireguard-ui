package handler

import (
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

// ContentTypeJson checks that the requests have the Content-Type header set to "application/json".
// This helps against CSRF attacks.
func ContentTypeJson(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		contentType := c.Request().Header.Get("Content-Type")
		if contentType != "application/json" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Only JSON allowed"})
		}

		return next(c)
	}
}

// CheckUserPermissions checks whether the user has the admin permissions to access the resource.
func CheckUserPermissions(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		if sess.Values["role"] == "admin" {
			return next(c)
		}
		return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Do not have the admin permissions to access this resource"})
	}
}
