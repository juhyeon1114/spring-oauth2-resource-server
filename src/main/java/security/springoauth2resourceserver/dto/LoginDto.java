package security.springoauth2resourceserver.dto;

import lombok.Data;

@Data
public class LoginDto {

    private String username;
    private String password;

}
