package com.client_certificate;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

@Configuration
public class RestClientCertTestConfiguration {

    private char[] caPassword;

    @Bean
    public RestTemplate restTemplate(@Value("${server.ssl.key-store-password}") String caPassword) throws Exception {

        this.caPassword = caPassword.toCharArray();

        SSLContext sslContext = SSLContextBuilder
                .create()
                .loadKeyMaterial(ResourceUtils.getFile("classpath:CA.p12"), this.caPassword, this.caPassword)
                .loadTrustMaterial(ResourceUtils.getFile("classpath:truststore.jks"), this.caPassword)
                .build();

        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();

        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(client));
    }
}
