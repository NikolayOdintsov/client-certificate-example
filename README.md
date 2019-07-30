## The applications is an example of Spring Boot V.2.+ app which can:
 - create client certificate signed with CA certificate
 - revoke client certificate
 - secure endpoint with client certificate authentication

# Getting Started (preparation)

#####1. Generate CA private key:
```
openssl genrsa -des3 -out CA.key 2048
```
*enter a passphrase for the key, in this example I used `mypass`*


#####2. Generate CA certificate and sign with private CA key:
```
openssl req -x509 -new -nodes -key CA.key -days 7300 -out CA.pem
```

#####3 .Generate p12 file from CA key and CA cert (pem):
```
openssl pkcs12 -export -in ~/CA.pem -inkey ~/CA.key -certfile ~/CA.pem -name "examplecert" -out CA.p12
```

#####4. Generate trust store:
```
keytool -import -file CA.pem -alias examplecert -keystore truststore.jks
```

*For more information read resources: https://stuff-things.net/2015/09/17/client-certificate-ca-setup-and-signing/*

# Getting Ready Web app to use CA certificate

1. Copy CA p12 file and truststore.jks files into resource folder of the app.
2. Add existing certificate revocation list file or create empty file (just create empty file with any name you like and update properties file).
3. Update application.properties file if needed (CA file names, subfolder if any, passwords, CA alias).


# Testing the app
To obtain client certificate:
```
curl -k https://localhost:8443/certificate/download --output ~/client.pem
```

To test client certificate:
```
curl -k --cert ~/client.pem https://localhost:8443/certificate/verify
```
