package security.springoauth2resourceserver;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig {

    private final OAuth2ResourceServerProperties properties;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .anyRequest()
                .authenticated();
        http.formLogin().permitAll();
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // jwt 토큰을 검증하는 Bean, Class 들을 생성하고 초기화 함
        return http.build();
    }

    // #1 Default JWT 디코더와 동일
    @Bean
    public JwtDecoder jwtDecoder1() {
        return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
    }

    // #2 Oidc 이슈어 URI 초기화
//    @Bean
//    public JwtDecoder jwtDecoder2() {
//        return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
//    }

    // #3 JWT 알고리즘을 변경하고 싶을 때
//    @Bean
//    public JwtDecoder jwtDecoder3() {
//        return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
//                .jwsAlgorithm(SignatureAlgorithm.RS512).build();
//    }

}
