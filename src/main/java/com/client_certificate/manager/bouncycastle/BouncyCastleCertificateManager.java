package com.client_certificate.manager.bouncycastle;

import com.client_certificate.manager.CertificateManager;
import com.client_certificate.manager.domain.ClientCertificate;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StopWatch;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

/**
 * Class is implementation of client certificate manager with BouncyCastle library (https://www.bouncycastle.org/)
 */
@Slf4j
@Component
public class BouncyCastleCertificateManager implements CertificateManager {
    private final String signatureAlgorithm = "SHA256withRSA";

    private final char[] CA_PASSWORD;
    private final String CA_CERTIFICATE_ALIAS;
    private CertificateAuthority ca;

    public BouncyCastleCertificateManager(@Value("${server.ssl.key-store-password}") String caPassword,
                                          @Value("${server.ssl.key-alias}") String caCertificateAlias,
                                          @Value("${server.ssl.key-store}") String caKeyStoreFile,
                                          @Value("${server.ssl.crl-file}") String caRevocationCertificateListFile)
            throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException, IOException {

        this.CA_PASSWORD = caPassword.toCharArray();
        this.CA_CERTIFICATE_ALIAS = caCertificateAlias;

        StopWatch watch = new StopWatch();
        watch.start();

        Security.addProvider(new BouncyCastleProvider());

        watch.stop();
        log.info("Execution time of adding BC as security provider in millis: {}", watch.getTotalTimeMillis());

        watch.start();

        //reading CA data
        this.ca = new CertificateAuthority(caKeyStoreFile, ResourceUtils.getFile(caRevocationCertificateListFile));

        watch.stop();
        log.info("Execution time of reading CA data took in millis: {}", watch.getTotalTimeMillis());
    }

    /**
     * Method generates client certificate signed with CA certificate.
     *
     * @param daysToBeValid Validity days for client certificate
     * @param clientCN      Common Name of client certificate (identifier of client)
     * @return X509Certificate
     * @throws Exception
     */
    @Override
    public X509Certificate generateClientX509Certificate(final int daysToBeValid, final String clientCN) throws Exception {
        //client RSA private key
        KeyPair keyPair = generateClientRSAKeyPair();

        //generate CSR
        PKCS10CertificationRequest csr = generateCSR(keyPair, clientCN);

        //sign CSR with CA certificate
        return signCSR(csr, daysToBeValid);
    }

    /**
     * Method generates client certificate signed with CA certificate.
     *
     * @param daysToBeValid Validity days for client certificate
     * @param clientCN      Common Name of client certificate (identifier of client)
     * @return ClientCertificate
     * @throws Exception
     */
    @Override
    public ClientCertificate generateClientCertificate(final int daysToBeValid, final String clientCN) throws Exception {
        //client RSA private key
        KeyPair keyPair = generateClientRSAKeyPair();

        //generate CSR
        PKCS10CertificationRequest csr = generateCSR(keyPair, clientCN);

        //sign CSR with CA certificate
        X509Certificate certificate = signCSR(csr, daysToBeValid);

        return new ClientCertificate(keyPair, csr, certificate);
    }

    @Override
    public void revokeCertificate(X509Certificate certificateToRevoke) throws IOException, OperatorCreationException {
        X500Name issuer = X500Name.getInstance((this.ca.certificate.getSubjectX500Principal().getEncoded()));

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());

        if (this.ca.revocationListFile != null && this.ca.revocationListFile.exists()) {
            byte[] data = readFileToByteArray(this.ca.revocationListFile);
            X509CRLHolder crl = new X509CRLHolder(data);
            crlBuilder.addCRL(crl);
        }

        crlBuilder.addCRLEntry(certificateToRevoke.getSerialNumber(), new Date(), CRLReason.privilegeWithdrawn);


        // build and sign CRL with CA private key
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(this.ca.privateKey);
        X509CRLHolder crl = crlBuilder.build(signer);


        File tmpFile = new File(this.ca.revocationListFile.getParentFile(), Long.toHexString(System.currentTimeMillis()) + ".tmp");
        log.info("CRL temp file: {}", tmpFile.getName());
        updateCRLFile(crl, tmpFile);
    }

    public void createCertificateRevocationList() throws IOException, OperatorCreationException {
        X500Name issuer = X500Name.getInstance((this.ca.certificate.getSubjectX500Principal().getEncoded()));

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());

        // build and sign CRL with CA private key
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(this.ca.privateKey);
        X509CRLHolder crl = crlBuilder.build(signer);


        File tmpFile = new File(this.ca.revocationListFile.getParentFile(), Long.toHexString(System.currentTimeMillis()) + ".tmp");
        log.info("CRL temp file: {}", tmpFile.getName());
        updateCRLFile(crl, tmpFile);
    }

    private KeyPair generateClientRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(4096, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    private PKCS10CertificationRequest generateCSR(final KeyPair keyPair, final String clientCN) throws OperatorCreationException {
        final String client_CN = "CN=" + clientCN;
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(client_CN), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());

        return p10Builder.build(signer);
    }

    private X509Certificate signCSR(PKCS10CertificationRequest inputCSR, int daysToBeValid) throws Exception {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        //These are the details of the CA
        X500Name issuer = X500Name.getInstance((this.ca.certificate.getSubjectX500Principal().getEncoded()));

        //This should be a serial number that the CA keeps track of
        BigInteger serial = new BigInteger(64, new SecureRandom());

        //Certificate validity start
        Date from = new Date();

        //Certificate validity end
        Date to = new Date(from.getTime() + daysToBeValid * 86400000L);

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(issuer, serial, from, to, inputCSR.getSubject(), inputCSR.getSubjectPublicKeyInfo());
        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(this.ca.privateKey.getEncoded()));
        X509CertificateHolder holder = v3CertGen.build(signer);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
    }

    private static byte[] readFileToByteArray(File file) {
        FileInputStream fis;
        byte[] bArray = new byte[(int) file.length()];
        try {
            fis = new FileInputStream(file);
            fis.read(bArray);
            fis.close();

        } catch (IOException ioExp) {
            ioExp.printStackTrace();
        }
        return bArray;
    }

    //TODO: refactor
    public void encrypt(X509Certificate cert, File source, File destination) throws CertificateEncodingException, IOException, CMSException {
        CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

        try (FileOutputStream fileStream = new FileOutputStream(destination);
             OutputStream encryptingStream = gen.open(fileStream, encryptor)) {

            byte[] unencryptedContent = Files.readAllBytes(source.toPath());
            encryptingStream.write(unencryptedContent);
        }

        System.out.println(String.format("Encrypted '%s' to '%s'", source.getAbsolutePath(), destination.getAbsolutePath()));

    }

    //TODO: refactor
    public void decrypt(PrivateKey privateKey, File encrypted, File decryptedDestination) throws IOException, CMSException {
        byte[] encryptedData = Files.readAllBytes(encrypted.toPath());

        CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(encryptedData);

        RecipientInformation recInfo = getSingleRecipient(parser);
        Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);

        try (InputStream decryptedStream = recInfo.getContentStream(recipient).getContentStream()) {
            Files.copy(decryptedStream, decryptedDestination.toPath());
        }

        System.out.println(String.format("Decrypted '%s' to '%s'", encrypted.getAbsolutePath(), decryptedDestination.getAbsolutePath()));
    }

    private RecipientInformation getSingleRecipient(CMSEnvelopedDataParser parser) {
        Collection recInfos = parser.getRecipientInfos().getRecipients();
        Iterator recipientIterator = recInfos.iterator();
        if (!recipientIterator.hasNext()) {
            throw new RuntimeException("Could not find recipient");
        }
        return (RecipientInformation) recipientIterator.next();
    }

    private void updateCRLFile(X509CRLHolder crl, File tmpFile) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
            fos.write(crl.getEncoded());
            fos.flush();
            fos.close();
            if (this.ca.revocationListFile.exists()) {
                this.ca.revocationListFile.delete();
            }
            tmpFile.renameTo(this.ca.revocationListFile);
        } finally {
            if (tmpFile.exists()) {
                tmpFile.delete();
            }
        }
    }


    class CertificateAuthority {
        private PrivateKey privateKey;
        private X509Certificate certificate;
        private File revocationListFile;

        CertificateAuthority(String caKeyStoreFile, File revocationListFile) throws CertificateException, UnrecoverableKeyException,
                NoSuchAlgorithmException, KeyStoreException, IOException {

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream(ResourceUtils.getFile(caKeyStoreFile)), CA_PASSWORD);

            X509Certificate caCertificate = (X509Certificate) keystore.getCertificate(CA_CERTIFICATE_ALIAS);

            this.privateKey = (PrivateKey) keystore.getKey(CA_CERTIFICATE_ALIAS, CA_PASSWORD);
            this.certificate = caCertificate;
            this.revocationListFile = revocationListFile;
        }
    }

}
