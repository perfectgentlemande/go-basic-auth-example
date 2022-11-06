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
