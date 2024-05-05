package main

import (
    "github.com/gin-gonic/gin"
	"net/http"
	"golang.org/x/crypto/bcrypt"
    "fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
	"strings"
	"database/sql"
    _ "github.com/go-sql-driver/mysql"

)
var db *sql.DB
var Inmemory bool

func initDB() (*sql.DB,error){
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/test")
    if err != nil {
        panic(err.Error())
    }
	err = db.Ping()
    if err != nil {
        return nil, err
    }
    return db,nil
}
var jwtKey = []byte("jwtsecretkey")

type user struct{
	Email string `json:"email"`
	Password string `json:"password"`

}
type userTable struct {
    id int `json:"id"`
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

func generateAuthToken( c *gin.Context,db *sql.DB){

	var newuser user
	if err:=c.BindJSON(&newuser);err!=nil{
		return
	}
	var pass string
	var err error
	if(!Inmemory){
	val,err:=fetchValuesFromDBForAuth(db,newuser)
	if err!=nil{
		fmt.Println(err)
	}
	pass=val.Password
	}else{
		var ok bool
	pass,ok=data[newuser.Email]
	if(!ok){
		c.IndentedJSON(http.StatusOK,"Incorrect creds")
		return
		}
	}
	if(err!=nil){
		c.IndentedJSON(http.StatusOK,"Incorrect creds")
		return
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


func login(c *gin.Context,db *sql.DB){
	var newuser user
	if err:=c.BindJSON(&newuser);err!=nil{
		return
	}
	pass:=""
	if(Inmemory){
		var ok bool
	pass,ok=data[newuser.Email]
	if(!ok){
		c.IndentedJSON(http.StatusOK, gin.H{"error": "user not found"})
		return
	}
	}else{
	val,err:=fetchValuesFromDBForAuth(db,newuser)
	if err!=nil{
		fmt.Println(err)
	}
	pass=val.Password
	}
	
	if(pass!=""){
	err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(newuser.Password))
    // fmt.Println(err)
	if(err==nil) {
		fmt.Println("success login")
	c.IndentedJSON(http.StatusOK,newuser)
	}else{
		c.IndentedJSON(http.StatusOK,"incorrect pass")
	}
	}else{
		c.IndentedJSON(http.StatusOK,"invalid user Please Signup")
	}
}

func signup(c *gin.Context,db *sql.DB){
	var newuser signInUser 
	if err:=c.BindJSON(&newuser);err!=nil{
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newuser.Password), bcrypt.DefaultCost)
    if err != nil {
        panic(err)
    }
	newuser.Password=string(hashedPassword)

	data[newuser.Email]=string(hashedPassword)
	newMeta:=metaData{
		Email:newuser.Email,
		Phone:newuser.Phone,
		City:newuser.City,
		UserType:newuser.UserType,
	}
	if(Inmemory){
	meta=append(meta,newMeta)
	fmt.Println("append")
	fmt.Println(meta)
	}else{
	err=insertValues(db,newuser)
	if(err!=nil){
		c.IndentedJSON(http.StatusBadRequest,"bad")
	}
	}
	
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


func dashboard(c *gin.Context,db *sql.DB){
	email := c.MustGet("email").(string)
	var userdata metaData
	if(email==""){
		c.JSON(http.StatusOK, gin.H{"email": "invalid mail"})
	}
	if(Inmemory){
	userdata,_=getDatafromLocalcache(email)
	}else{
	userdata,_=fetchValuesFromDBForDash(db,email)
	}
    c.JSON(http.StatusOK, gin.H{"email": userdata})

}

func getDatafromLocalcache(mail string) (metaData,error){
	var metanew metaData
	fmt.Println(meta)
	fmt.Println(mail)
	for i:=range(meta){
		if meta[i].Email==mail{
			fmt.Println(meta[i])
			metanew=meta[i]
			return metanew,nil
		}
	}

return metanew,nil
}

func createTable(db *sql.DB) error{
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS userData (id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, email TEXT NOT NULL, password TEXT NOT NULL,phone BIGINT NOT NULL, city TEXT NOT NULL,userType TEXT NOT NULL)")
    if err != nil {
        // panic(err)
		return err
    }
	return nil

}
func insertValues(db *sql.DB,user signInUser) error{

	stmt, err := db.Prepare("INSERT INTO userData (email,password,phone,city,userType) VALUES (?,?,?,?,?)")
	if err != nil {
		panic(err.Error())
	}
	defer stmt.Close()
	_, err = stmt.Exec(user.Email,user.Password,user.Phone,user.City,user.UserType)
	if err != nil {
		panic(err.Error())
	}
	return nil

}

func fetchValuesFromDBForAuth(db *sql.DB,User user) (user ,error){
	
	results, err := db.Query("SELECT email,password FROM userData where email=?",User.Email)
	
	// results, err := db.Query("SELECT email,password FROM userData")
	var testtable2 user
    if err !=nil {
        panic(err.Error())
    }
    for results.Next() {
		// var u user
        err = results.Scan(&testtable2.Email,&testtable2.Password)
        if err !=nil {
            panic(err.Error())
        }
		// testtable2=append(testtable2,u)
        // fmt.Println(testtable2.Email)
		// fmt.Println(testtable2.Password)
    }
	return testtable2,nil
}


func fetchValuesFromDBForDash(db *sql.DB,email string) (metaData ,error){
	
	results, err := db.Query("SELECT email,phone,city,userType FROM userData where email=?",email)
	
	// results, err := db.Query("SELECT email,password FROM userData")
	var testtable2 metaData
    if err !=nil {
        panic(err.Error())
    }
    for results.Next() {
		// var u user
        err = results.Scan(&testtable2.Email,&testtable2.Phone,&testtable2.City,&testtable2.UserType)
        if err !=nil {
            panic(err.Error())
        }
		// testtable2=append(testtable2,u)
        // fmt.Println(testtable2.Email)
		// fmt.Println(testtable2.Password)
    }
	// testtable2.Password=""
	return testtable2,nil
}

func fetchValuesFromDB(db *sql.DB) ([]user ,error){
	results, err := db.Query("SELECT email,password FROM userData")
	var testtable2 []user
    if err !=nil {
        panic(err.Error())
    }
    for results.Next() {
		var u user
        err = results.Scan(&u.Email,&u.Password)
        if err !=nil {
            panic(err.Error())
        }
		testtable2=append(testtable2,u)
        // fmt.Println(testtable2.Email)
		// fmt.Println(testtable2.Password)
    }
	return testtable2,nil
}

func main(){
	Inmemory=false	
	var err error
	if(!Inmemory){
	fmt.Println("database")
	db, err = initDB()
    if err != nil {
        panic(err.Error())
    }
    defer db.Close()

	err= createTable(db)
	if err != nil {
        panic(err.Error())
    }
	}else{
		fmt.Println("In memory ")
	}

	router:=gin.Default();
	router.POST("/signup",func(c *gin.Context) {
		signup(c, db)
	})
	router.POST("/login",func(c *gin.Context) {
		login(c, db)
	})
	router.POST("/token",func(c *gin.Context) {
		generateAuthToken(c, db)
	})
	auth:=router.Group("/")
	auth.Use(authorize)
	{
		auth.GET("/dashboard",func(c *gin.Context) {
			dashboard(c, db)
		})
	}
	router.Run("localhost:5000")
}



