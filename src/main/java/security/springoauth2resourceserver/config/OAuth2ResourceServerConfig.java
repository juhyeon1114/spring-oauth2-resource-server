package security.springoauth2resourceserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import security.springoauth2resourceserver.filter.authentication.JwtAuthenticationFilter;
import security.springoauth2resourceserver.filter.authorization.JwtAuthorizationMacFilter;
import security.springoauth2resourceserver.filter.authorization.JwtAuthorizationRsaFilter;
import security.springoauth2resourceserver.signature.MacSecuritySigner;
import security.springoauth2resourceserver.signature.RsaSecuritySigner;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig {

    private final MacSecuritySigner macSecuritySigner;
    private final OctetSequenceKey octetSequenceKey;
    private final OAuth2ResourceServerProperties properties;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable(); // 개발환경에서는 disable
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // Token 을 사용하므로 세션은 사용할 필요 없음

        http.authorizeHttpRequests()
                .requestMatchers("/", "/login").permitAll()
                .anyRequest()
                .authenticated();

        http.userDetailsService(userDetailsService());

        /* MAC */
        /* - 사용자 승인, 토큰 서명, 발행을 담당하는 필터 */
//        http.addFilterBefore(jwtAuthenticationFilter(macSecuritySigner, octetSequenceKey), UsernamePasswordAuthenticationFilter.class);
        /* - 토큰 검증  */
//        http.addFilterBefore(jwtAuthorizationMacFilter(octetSequenceKey), UsernamePasswordAuthenticationFilter.class); // AuthorizationFilter 로 검증하기
//        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // JWT 디코더로 검증하기

        /* RSA */
        /* - 사용자 승인, 토큰 서명, 발행을 담당하는 필터 */
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
        /* - 토큰 검증  */
        http.addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * RSA 방식
     */
    public Filter jwtAuthenticationFilter(RsaSecuritySigner rsaSecuritySigner, RSAKey rsaKey) {
        return new JwtAuthenticationFilter(rsaSecuritySigner, rsaKey);
    }

    /**
     * MAC 방식
     */
//    public Filter jwtAuthenticationFilter(MacSecuritySigner macSecuritySigner, OctetSequenceKey octetSequenceKey) {
//        return new JwtAuthenticationFilter(macSecuritySigner, octetSequenceKey);
//    }

    @Bean
    public Filter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
    }

    @Bean
    public Filter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // 개발, 테스트용
    }


}
