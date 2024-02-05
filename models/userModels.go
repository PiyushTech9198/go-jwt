package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID            primitive.ObjectID `bson:"_id"`
	First_name    *string            `json:"first_name" validate:"required,min=2,max=100"`
	Last_name     *string            `json:"last_name" validate:"required,min=2,max=100"`
	Password      *string            `json:"password" validate:"required,min=6"`
	Email         *string            `json:"email" validate:"email,required"`
	Phone         *string            `json:"phone"`
	Token         *string            `json:"token"`
	User_Type     *string            `json:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	Refresh_token *string            `json:"refresh_token"`
	Created_at    time.Time          `json:"create_at"`
	Update_at     time.Time          `json:"update_at"`
	User_id       string             `json:"user_id"`
}

// {
//     "first_name":"piyush",
//     "last_name":"bhatnagar",
//     "password":"1234567",
//     "email":"piyush@gmail.com",
//     "phone":"1234567890",
//     "user_type":"ADMIN"

// }
