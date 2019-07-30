package com.client_certificate.secured_api.configuration;

import com.client_certificate.manager.CertificateManager;
import com.client_certificate.manager.bouncycastle.BouncyCastleCertificateManager;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.*;
import java.util.Arrays;

/**
 * Web filter to verify validity of client certificate:
 * - is certificate date is valid
 * - is it revoked
 */
@Component
@Slf4j
public class CustomX509ValidationFilter implements Filter {

    private X509CRL certificateRevocationList;

    @Autowired
    public CustomX509ValidationFilter(@Value("${server.ssl.key-store-password}") String caPassword,
                                      @Value("${server.ssl.key-alias}") String caCertificateAlias,
                                      @Value("${server.ssl.key-store}") String caKeyStoreFile,
                                      @Value("${server.ssl.crl-file}") String caRevocationCertificateListFile) throws CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
            IOException, OperatorCreationException, CRLException {


        CertificateFactory cf = CertificateFactory.getInstance("X509");
        try {
            this.certificateRevocationList = (X509CRL) cf.generateCRL(new FileInputStream(ResourceUtils.getFile(caRevocationCertificateListFile)));
        } catch (CRLException | FileNotFoundException e) {
            CertificateManager certificateManager = new BouncyCastleCertificateManager(caPassword, caCertificateAlias, caKeyStoreFile, caRevocationCertificateListFile);
            certificateManager.createCertificateRevocationList();
            this.certificateRevocationList = (X509CRL) cf.generateCRL(new FileInputStream(ResourceUtils.getFile(caRevocationCertificateListFile)));
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        boolean invalid = false;

        if (request instanceof HttpServletRequest) {
            String url = ((HttpServletRequest) request).getRequestURI();
            if (certs == null && Arrays.asList(WebSecurityConfig.WHITELISTED_URL).contains(url)) {
                certs = new X509Certificate[0];
            }
        }


        assert certs != null;
        for (X509Certificate certificate : certs) {
            try {
                certificate.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                log.error("Invalid validity date for certificate SN: {}", certificate.getSerialNumber());
                invalid = true;
            }

            X509CRLEntry revokedCertificate = certificateRevocationList.getRevokedCertificate(certificate.getSerialNumber());
            if (revokedCertificate != null) {
                log.error("Revoked certificate SN: {}", certificate.getSerialNumber());
                invalid = true;
            }
        }


        if (!invalid)
            chain.doFilter(request, response);

    }

    @Override
    public void destroy() {

    }
}
