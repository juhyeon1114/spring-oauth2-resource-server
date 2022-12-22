package security.springoauth2resourceserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "/";
    }

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication) {
        return authentication;
    }

}
