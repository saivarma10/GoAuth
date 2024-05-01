package main

import (
    "github.com/gin-gonic/gin"
	"net/http"
	"golang.org/x/crypto/bcrypt"
    "fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
	"strings"
)
var jwtKey = []byte("jwtsecretkey")

type user struct{
	Email string `json:"email"`
	Password string `json:"password"`

}


type signInUser struct{
	Email string `json:"email"`
	Password string `json:"password"`
	Phone int64 `json:phone`
	City string `json:city`
	UserType string `json:usertype`

}

var data = make(map[string]string)

type metaData struct{
	Email string `json:"email"`
	Phone int64 `json:phone`
	City string `json:city`
	UserType string `json:usertype`

}

var meta []metaData
type createUser struct{

	Email string `json:"email`
	Password string `json:"password"`

}

func generateAuthToken( c *gin.Context){

	var newuser user
	if err:=c.BindJSON(&newuser);err!=nil{
		return
	}
	pass,ok:=data[newuser.Email]
	if(!ok){
		c.IndentedJSON(http.StatusOK,"Incorrect creds")
	}else{
		err:=bcrypt.CompareHashAndPassword([]byte(pass),[]byte(newuser.Password))
		if err!=nil{
			c.IndentedJSON(http.StatusOK,"Incorrect password")
		}
	}
	expirationTime := time.Now().Add(24 * time.Hour)
    claims := &jwt.StandardClaims{
        ExpiresAt: expirationTime.Unix(),
        Subject:   newuser.Email,
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }
    c.IndentedJSON(http.StatusOK, gin.H{"token": tokenString})



}


func login(c *gin.Context){
	var newuser user
	if err:=c.BindJSON(&newuser);err!=nil{
		return
	}
	pass,ok:=data[newuser.Email]
	if(ok){
	err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(newuser.Password))
    fmt.Println(err)
	if(err==nil) {
	c.IndentedJSON(http.StatusOK,newuser)
	}else{
		c.IndentedJSON(http.StatusOK,"incorrect pass")
	}
	}else{
		c.IndentedJSON(http.StatusOK,"invalid user Please Signup")
	}
}

func signup(c *gin.Context){
	var newuser signInUser 
	if err:=c.BindJSON(&newuser);err!=nil{
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newuser.Password), bcrypt.DefaultCost)
    if err != nil {
        panic(err)
    }

	data[newuser.Email]=string(hashedPassword)
	newMeta:=metaData{
		Email:newuser.Email,
		Phone:newuser.Phone,
		City:newuser.City,
		UserType:newuser.UserType,
	}
	meta=append(meta,newMeta)
	fmt.Println("append")
	fmt.Println(meta)
	c.IndentedJSON(http.StatusOK,newuser)


}



func authorize(c *gin.Context) {
    tokenString, err := c.Cookie("token")
    if err != nil {
		tokenString = c.GetHeader("Authorization")
		if tokenString==""{
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        c.Abort()
        return
		}
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
    }

    claims := &jwt.StandardClaims{}

    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })

    if err != nil {
        if err == jwt.ErrSignatureInvalid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
            c.Abort()
            return
        }
        c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
        c.Abort()
        return
    }
    if !token.Valid {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        c.Abort()
        return
    }
	fmt.Println("sub"+claims.Subject)
	c.Set("email", claims.Subject)


    c.Next()
}


func dashboard(c *gin.Context){
	email := c.MustGet("email").(string)
	if(email==""){
		c.JSON(http.StatusOK, gin.H{"email": "invalid mail"})
	}
	userdata,_:=getDatafromDB(email)
	
    c.JSON(http.StatusOK, gin.H{"email": userdata})

}

func getDatafromDB(mail string) (metaData,error){
	var metanew metaData
	fmt.Println(meta)
	for i:=range(meta){
		if meta[i].Email==mail{
			fmt.Println(meta[i])
			metanew=meta[i]
			return metanew,nil
		}
	}

return metanew,nil
}


func main(){
	router:=gin.Default();
	router.POST("/signup",signup)
	router.POST("/login",login)
	router.POST("/token",generateAuthToken)
	auth:=router.Group("/")
	auth.Use(authorize)
	{
		auth.GET("/dashboard",dashboard)
	}
	router.Run("localhost:5000")
}



