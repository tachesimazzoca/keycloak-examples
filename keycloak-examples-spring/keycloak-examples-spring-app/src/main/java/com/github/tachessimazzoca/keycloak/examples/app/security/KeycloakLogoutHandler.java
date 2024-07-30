package com.github.tachessimazzoca.keycloak.examples.app.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Component
public class KeycloakLogoutHandler implements LogoutHandler {

  private static final String KEYCLOAK_LOGOUT = "protocol/openid-connect/logout";

  private final RestTemplate restTemplate;

  public KeycloakLogoutHandler(@Qualifier("keycloakRestTemplate") RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
  }

  @Override
  public void logout(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    if (Objects.isNull(authentication)) {
      log.debug("There is no authentication state. Skip logging out from Keycloak.");
      return;
    }
    Object user = authentication.getPrincipal();
    if (user instanceof OidcUser) {
      logoutFromKeycloak((OidcUser) user);
    }
  }

  private void logoutFromKeycloak(OidcUser user) {
    try {
      URI uri = new URI(user.getIssuer() + "/").resolve(KEYCLOAK_LOGOUT);
      log.info("Keycloak logout URI:{}", uri);
      UriComponentsBuilder builder =
          UriComponentsBuilder.fromUri(uri)
              .queryParam("id_token_hint", user.getIdToken().getTokenValue());
      ResponseEntity<String> response =
          restTemplate.getForEntity(builder.toUriString(), String.class);
      if (!response.getStatusCode().is2xxSuccessful()) {
        log.warn("Keycloak logout failed. Please check the response from Keycloak; {}", response);
      }
    } catch (URISyntaxException e) {
      log.error("Building Keycloak logout URI failed; {}", e.getMessage(), e);
    } catch (RestClientException e) {
      log.warn("Keycloak logout failed. Skip retrying logout attempts; {}", e.getMessage(), e);
    }
  }
}
