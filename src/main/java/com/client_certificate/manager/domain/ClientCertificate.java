package com.client_certificate.manager.domain;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * Class is holder for CA related data
 */
public class ClientCertificate {
    private KeyPair keyPair;
    private PKCS10CertificationRequest csr;
    private X509Certificate certificate;

    public ClientCertificate(KeyPair keyPair, PKCS10CertificationRequest csr, X509Certificate certificate) {
        this.keyPair = keyPair;
        this.csr = csr;
        this.certificate = certificate;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public PKCS10CertificationRequest getCsr() {
        return csr;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
