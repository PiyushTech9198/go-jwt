package routes

import (
	"go-jwt/controller"

	"github.com/gin-gonic/gin"
)

func AuthRouters(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/user/signUp", controller.SignUp())

	incomingRoutes.POST("/user/login", controller.Login())
}
