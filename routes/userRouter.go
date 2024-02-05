package routes

import (
	"go-jwt/controller"
	"go-jwt/middleware"

	"github.com/gin-gonic/gin"
)

func UserRouter(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users:user_id", controller.GetUser())

}
