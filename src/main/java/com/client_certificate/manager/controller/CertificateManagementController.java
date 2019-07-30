package com.client_certificate.manager.controller;

import com.client_certificate.manager.CertificateManager;
import com.client_certificate.manager.domain.ClientCertificate;
import com.client_certificate.manager.utils.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;

/**
 * This is just a simple controller to show how client certificate PEM file could be downloaded.
 */
@Controller
public class CertificateManagementController {

    @Autowired
    private CertificateManager certificateManager;

    @Autowired
    private FileUtils fileUtils;

    /**
     * Generates client certificate, creates PEM file.
     *
     * @return client.pem file
     * @throws Exception
     */
    @RequestMapping(path = "/certificate/download", method = RequestMethod.GET)
    public ResponseEntity<Resource> download() throws Exception {

        ClientCertificate clientCertificate = certificateManager.generateClientCertificate(365, "localhost");
        String clientCertificateToWrite = fileUtils.generateClientCertificatePEMFileContent(clientCertificate);

        File tmpFile = File.createTempFile("client", ".pem");
        FileWriter writer = new FileWriter(tmpFile);
        writer.write(clientCertificateToWrite);
        writer.close();


        String fileName = "client.pem";
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-disposition", "attachment; filename=" + fileName);

        InputStreamResource resource = new InputStreamResource(new FileInputStream(tmpFile));

        return ResponseEntity.ok()
                .headers(headers)
                .contentLength(tmpFile.length())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }
}
