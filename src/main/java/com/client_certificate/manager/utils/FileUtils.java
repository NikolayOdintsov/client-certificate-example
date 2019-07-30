package com.client_certificate.manager.utils;

import com.client_certificate.manager.domain.ClientCertificate;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Component;
import sun.misc.BASE64Encoder;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

//TODO: refactor
@Component
public class FileUtils {
    private final BASE64Encoder base64Encoder = new BASE64Encoder();

    public String generateClientCertificatePEMFileContent(ClientCertificate clientCertificate) throws IOException {
        return generatePemFileString(clientCertificate.getKeyPair().getPrivate(), clientCertificate.getCertificate());
    }

    public void writePEMFile(ClientCertificate clientCertificate) throws IOException {
        //PEM file with RSA key and client certificate
        String certPemFileContent = generatePemFileString(clientCertificate.getKeyPair().getPrivate(), clientCertificate.getCertificate());
        writePemFile(certPemFileContent);
    }

    private void writePemFile(final String content) throws IOException {
        try (BufferedWriter out = new BufferedWriter(new FileWriter("client.pem"))) {
            out.write(content);
        }
    }

    private void writeClientKeyPairToFiles(final KeyPair keyPair) throws IOException {
        Key pubKey = keyPair.getPublic();
        Key privKey = keyPair.getPrivate();

        try (BufferedWriter out = new BufferedWriter(new FileWriter("clientPublic.key"))) {
            out.write(base64Encoder.encode(pubKey.getEncoded()));
        }

        try (BufferedWriter out = new BufferedWriter(new FileWriter("client.key"))) {
            out.write("-----BEGIN RSA PRIVATE KEY-----");
            out.newLine();
            out.write(base64Encoder.encode(privKey.getEncoded()));
            out.newLine();
            out.write("-----END RSA PRIVATE KEY-----");
            out.newLine();
        }
    }

    private void writeCSRToFile(PKCS10CertificationRequest csr) {
        //CSR to file
        try (BufferedWriter out = new BufferedWriter(new FileWriter("client.csr"))) {
            out.write("-----BEGIN CERTIFICATE REQUEST-----");
            out.newLine();
            out.write(base64Encoder.encode(csr.getEncoded()));
            out.newLine();
            out.write("-----END CERTIFICATE REQUEST-----");
            out.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String generatePemFileString(final Key clientPrivateKey, final X509Certificate clientCertificate) throws IOException {
        String newLine = "\r\n";
        //private RSA key
        String result = "-----BEGIN RSA PRIVATE KEY-----";
        result = result.concat(newLine);
        result = result.concat(base64Encoder.encode(clientPrivateKey.getEncoded()));
        result = result.concat(newLine);
        result = result.concat("-----END RSA PRIVATE KEY-----");
        result = result.concat(newLine);

        //client certificate
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(clientCertificate);
        pemWriter.flush();
        pemWriter.close();
        result = result.concat(writer.toString());

        return result;
    }
}
