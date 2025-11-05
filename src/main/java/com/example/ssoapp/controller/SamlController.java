package com.example.ssoapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SamlController {

    // Initiate SAML login manually
    @GetMapping("/sso/saml/login")
    public String samlLogin() {
        return "redirect:/saml2/authenticate/miniorange-saml";
    }

    // Expose SP metadata for miniOrange to read
    @GetMapping("/sso/saml/metadata")
    public String samlMetadata() {
        return "redirect:/saml2/service-provider-metadata/miniorange-saml";
    }
}
