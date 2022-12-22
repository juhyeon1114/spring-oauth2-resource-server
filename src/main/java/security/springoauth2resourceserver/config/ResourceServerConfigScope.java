package security.springoauth2resourceserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import security.springoauth2resourceserver.filter.authentication.JwtAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class ResourceServerConfigScope {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {



        http.authorizeHttpRequests()
                .requestMatchers("/photos/1").hasAuthority("SCOPE_photo")
                .requestMatchers("/photos/2").permitAll()
                .requestMatchers("/photos/3").permitAll()
                .requestMatchers("/photos/custom-role").hasAnyAuthority("ROLE_user", "ROLE_default-roles-oauth2")
                .anyRequest().authenticated();

//        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        /**
         * 커스텀한 권한 설정을 적용
         */
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomRoleConvert());
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);

        return http.build();
    }

}
