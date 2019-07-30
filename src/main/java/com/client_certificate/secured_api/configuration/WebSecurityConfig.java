package com.client_certificate.secured_api.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String WHITELISTED_URL[] = {"/certificate/download"};

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //we allow to access endpoint to get client certificate
                .antMatchers(WHITELISTED_URL)
                .permitAll()
                .and()
                //this part for all other requests which needed client certificate
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .x509()
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService());
    }

    /**
     * Simple implementation of client certificate user name validation.
     */
    @Bean
    public UserDetailsService userDetailsService() {

        return username -> {
            if (username.equals("localhost")) {
                return new User(username, "", AuthorityUtils.createAuthorityList("ROLE_SSL_USER"));
            }
            return null;
        };
    }

}
