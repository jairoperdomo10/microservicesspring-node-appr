package com.abcComp.hr.lms.code.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.beans.factory.annotation.Autowired;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import org.springframework.security.oauth2.jwt.Jwt;

@Configuration
@EnableWebSecurity
public class securityModule extends WebSecurityConfigurerAdapter {

    @Autowired
    XsuaaServiceConfiguration xsuaaServiceConfiguration;

    Converter<Jwt, AbstractAuthenticationToken> getJwtAuthoritiesConverter() {
        TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
        converter.setLocalScopeAsAuthorities(true); // not applicable in case of multiple xsuaa bindings!
        return converter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests().antMatchers("/Students").hasAuthority("readDataJP").antMatchers("/Students/**")
                .denyAll().anyRequest().denyAll().and().oauth2ResourceServer().jwt()
                .jwtAuthenticationConverter(getJwtAuthoritiesConverter());

    }
}