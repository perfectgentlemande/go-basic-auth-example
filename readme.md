# go-basic-auth-example
Example of authentication service using basic auth.  

Includes:    
- basic auth;  
- go-chi;  
- logrus;  
- Docker;
- Docker Compose.

## Description

Sample project for educational purposes.  
There are 3 key takeaways:  
- implementing quite simple authentication service (toke issuing + verification);
- checking and glueing together technologies mentioned above;
- sharing my own experience for the ones who want to glue the same technologies.

### Running

Use `go run .` from the folder that contains `main.go`.

### Running via Docker (no compose)

Build the app image and run:  
- `docker build -t go-basic-auth-app:v0.1.0 .`  
- `docker run -it -p 8080:80 --name go-basic-auth-app-0 go-basic-auth-app:v0.1.0`  

### Examples

For tst_usr_01/tst_pwd_01 from config. To get the Basic... string you should enconde to base64 your credentials. You can do this via Postman.  

`POST /login` to issue the token:    
- `curl --location --request POST 'http://localhost:8080/login' --header 'Authorization: Basic dHN0X3Vzcl8wMTp0c3RfcHdkXzAx'`
`POST /verify` to verify the token:    
- `curl --location --request POST 'http://localhost:8080/verify' --header 'Content-Type: application/json' --data-raw '{"token": "your.jwt.token"}'`