package com.client_certificate.manager;

import com.client_certificate.manager.domain.ClientCertificate;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.cert.X509Certificate;

public interface CertificateManager {

    X509Certificate generateClientX509Certificate(final int daysToBeValid, final String clientCN) throws Exception;

    ClientCertificate generateClientCertificate(final int daysToBeValid, final String clientCN) throws Exception;

    void revokeCertificate(final X509Certificate certificateToRevoke) throws Exception;

    void createCertificateRevocationList() throws IOException, OperatorCreationException;

}
