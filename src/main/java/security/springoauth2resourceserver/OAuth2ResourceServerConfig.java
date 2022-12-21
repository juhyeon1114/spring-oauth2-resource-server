package security.springoauth2resourceserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests()
                .anyRequest()
                .authenticated();

        http.formLogin().permitAll();

        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // jwt 토큰을 검증하는 Bean, Class 들을 생성하고 초기화 함

        return http.build();

    }

}
