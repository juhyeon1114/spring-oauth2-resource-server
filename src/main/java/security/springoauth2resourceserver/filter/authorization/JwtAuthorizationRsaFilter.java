package security.springoauth2resourceserver.filter.authorization;

import com.nimbusds.jose.JWSVerifier;

public class JwtAuthorizationRsaFilter extends JwtAuthorizationFilter {
    public JwtAuthorizationRsaFilter(JWSVerifier jwsVerifier) {
        super(jwsVerifier);
    }
}
