package security.springoauth2resourceserver.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "/";
    }

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication, @AuthenticationPrincipal Jwt principal) throws URISyntaxException {
    
        // 인증객체, 인증객체의 정보 조회하기
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
        Object sub1 = authenticationToken.getTokenAttributes().get("sub");
        Object email1 = authenticationToken.getTokenAttributes().get("email");
        Object scope1 = authenticationToken.getTokenAttributes().get("scope");
        String sub2 = principal.getClaim("sub");
        String token = principal.getTokenValue();// Client 에서 전송된 토큰

        // 다른 곳(서버)에 클라이언트에서 넘어온 토큰을 활용해서 요청하기
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        RequestEntity<String> request = new RequestEntity<>(headers, HttpMethod.GET, new URI("http://localhost:8082"));
        ResponseEntity<String> response = restTemplate.exchange(request, String.class);
        String body = response.getBody();

        return authentication;
    }

}
