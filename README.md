SecureSpace is a secure messaging web application inspired by Twitter, allowing users to publish messages with digital signatures.  
Each message can be cryptographically verified, ensuring the authenticity of its author.  

App is containerized using Docker + Docker Compose, secured with SSL/TLS (Nginx), and features two-factor authentication (TOTP).

---
To build app and start the containers:
**docker-compose up --build**
