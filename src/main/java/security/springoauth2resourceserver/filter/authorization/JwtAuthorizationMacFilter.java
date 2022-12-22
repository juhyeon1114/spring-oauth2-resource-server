package security.springoauth2resourceserver.filter.authorization;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

public class JwtAuthorizationMacFilter extends OncePerRequestFilter {

    private OctetSequenceKey octetSequenceKey;

    public JwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) {
        this.octetSequenceKey = octetSequenceKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 토큰 형식 유효성 검증
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // 다음필터로 넘김
        }

        String token = header.replace("Bearer ", "");

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);// 문자열 토큰이 header, payload, signature 값이 따로 파싱이됨
            MACVerifier macVerifier = new MACVerifier(octetSequenceKey.toSecretKey());
            boolean verify = signedJWT.verify(macVerifier);

            if (verify) {
                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
                String username = jwtClaimsSet.getClaim("username").toString();
                List<String> authority = (List<String>) jwtClaimsSet.getClaim("authority");

                if (username != null) {
                    UserDetails user = User.withUsername(username)
                            .password(UUID.randomUUID().toString())
                            .authorities(authority.get(0))
                            .build();

                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            user.getAuthorities());

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        } finally {
            filterChain.doFilter(request, response); // 다음필터로 넘김
        }

    }
}
