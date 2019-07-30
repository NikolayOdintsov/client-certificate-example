package com.client_certificate.secured_api.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/certificate")
public class ServerController {

    @RequestMapping(path = "/verify", method = RequestMethod.GET)
    public String verify() {
        log.info("Called rest api");

        return "Hello";
    }
}
