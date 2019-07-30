package com.client_certificate;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.NoSuchAlgorithmException;

@Slf4j
@SpringBootApplication
public class ClientCertificateExampleApplication {

    public static void main(String[] args) throws NoSuchAlgorithmException {


        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        log.info("=========================================================");
        log.info("Max Key Size for AES : {}", maxKeySize);
        log.info("=========================================================");

        SpringApplication.run(ClientCertificateExampleApplication.class, args);
    }

}
