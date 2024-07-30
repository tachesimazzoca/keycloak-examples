package com.github.tachessimazzoca.keycloak.examples.app.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

  @GetMapping("/")
  public String index() {
    return "index";
  }

  @GetMapping("/dashboard")
  public String dashboard(Authentication authentication) {
    return authentication.getPrincipal().toString();
  }
}
