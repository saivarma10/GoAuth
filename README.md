# GolanG Token Auth and Sql conenction
<p>This program is used for learning connection with mysql DB using Golang and JWT token authorisation , password hashing using bcrypt </p>


# Sample Curl Commands 
1. Signup
Endpoint: POST /signup

curl -X POST http://localhost:5000/signup \
-H "Content-Type: application/json" \
-d '{
    "email": "varmasai10@gmail.com",
    "password": "yourpassword",
    "phone": 1234567890,
    "city": "YourCity",
    "usertype": "YourUserType"
}'


2. Login
Endpoint: POST /login

curl -X POST http://localhost:5000/login \
-H "Content-Type: application/json" \
-d '{
    "email": "varmasai10@gmail.com",
    "password": "yourpassword"
}'


3. Generate Auth Token
Endpoint: POST /token

curl -X POST http://localhost:5000/token \
-H "Content-Type: application/json" \
-d '{
    "email": "varmasai10@gmail.com",
    "password": "yourpassword"
}'


4. Dashboard (Authorized)
Endpoint: GET /dashboard


curl -X GET http://localhost:5000/dashboard \
-H "Authorization: Bearer YOUR_JWT_TOKEN"



