package com.github.tachessimazzoca.keycloak.examples.app.config;

import com.github.tachessimazzoca.keycloak.examples.app.security.KeycloakLogoutHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  private static final String CLAIM_ROLES = "roles";

  private static final String CLAIM_REALM_ACCESS = "realm_access";

  private final KeycloakLogoutHandler keycloakLogoutHandler;

  WebSecurityConfig(KeycloakLogoutHandler keycloakLogoutHandler) {
    this.keycloakLogoutHandler = keycloakLogoutHandler;
  }

  @Bean
  public SessionRegistry sessionRegistry() {
    return new SessionRegistryImpl();
  }

  @Bean
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(sessionRegistry());
  }

  @Bean
  public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
        (requests) ->
            requests
                .requestMatchers(new AntPathRequestMatcher("/"))
                .permitAll()
                .anyRequest()
                .authenticated());
    http.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
    http.oauth2Login(Customizer.withDefaults())
        .logout(
            (logout) ->
                logout
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .addLogoutHandler(keycloakLogoutHandler)
                    .logoutSuccessUrl("/"));
    return http.build();
  }

  @Bean
  public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
    return authorities -> {
      return authorities.stream()
          .findFirst()
          .map(
              (authority) -> {
                if (authority instanceof OidcUserAuthority) {
                  return convertToGrantedAuthorities((OidcUserAuthority) authority);
                } else {
                  return convertToGrantedAuthorities((OAuth2UserAuthority) authority);
                }
              })
          .orElse(Collections.emptySet());
    };
  }

  private Set<GrantedAuthority> convertToGrantedAuthorities(OidcUserAuthority authority) {
    Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
    OidcUserInfo userInfo = authority.getUserInfo();
    if (userInfo.hasClaim(CLAIM_REALM_ACCESS)) {
      Map<String, Object> realmAccessMap = userInfo.getClaimAsMap(CLAIM_REALM_ACCESS);
      return mapToGrantedAuthorities((Collection<String>) realmAccessMap.get(CLAIM_ROLES));
    }
    return grantedAuthorities;
  }

  private Set<GrantedAuthority> convertToGrantedAuthorities(OAuth2UserAuthority authority) {
    Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
    // TODO: Support OAuth2
    return grantedAuthorities;
  }

  private Set<GrantedAuthority> mapToGrantedAuthorities(Collection<String> roles) {
    return roles.stream()
        .map((role) -> new SimpleGrantedAuthority("ROLE_" + role))
        .collect(Collectors.toSet());
  }
}
