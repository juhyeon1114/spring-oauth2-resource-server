package security.springoauth2resourceserver.config;

import com.nimbusds.jose.JOSEException;
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
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
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

//@Configuration
@RequiredArgsConstructor
public class ResourceServerConfigAuth {

    private final MacSecuritySigner macSecuritySigner;
    private final OctetSequenceKey octetSequenceKey;
    private final OAuth2ResourceServerProperties properties;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable(); // ????????????????????? disable
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // Token ??? ??????????????? ????????? ????????? ?????? ??????

        http.authorizeHttpRequests()
                .requestMatchers("/", "/login").permitAll()
                .anyRequest()
                .authenticated();

        http.userDetailsService(userDetailsService());

        /* - ????????? ??????, ?????? ??????, ????????? ???????????? ?????? */
//        http.addFilterBefore(jwtAuthenticationFilter(macSecuritySigner, octetSequenceKey), UsernamePasswordAuthenticationFilter.class); // MAC
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class); // RSA

        /* - ?????? ?????? #1 : JWT ?????????  */
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        /* - ?????? ?????? #2 : AuthorizationFilter  */
//        http.addFilterBefore(jwtAuthorizationMacFilter(octetSequenceKey), UsernamePasswordAuthenticationFilter.class); // MAC
        http.addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class); // RSA

        return http.build();
    }

    /**
     * RSA ??????
     */
    public Filter jwtAuthenticationFilter(RsaSecuritySigner rsaSecuritySigner, RSAKey rsaKey) {
        return new JwtAuthenticationFilter(rsaSecuritySigner, rsaKey);
    }

    /**
     * MAC ??????
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
        return NoOpPasswordEncoder.getInstance(); // ??????, ????????????
    }


}
