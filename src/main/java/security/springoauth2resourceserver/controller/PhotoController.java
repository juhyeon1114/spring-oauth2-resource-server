package security.springoauth2resourceserver.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import security.springoauth2resourceserver.dto.Photo;

@RestController
public class PhotoController {

    @GetMapping("/photos/1")
    public Photo photos1() {
        return Photo.builder()
                .photoId("1")
                .photoDescription("photo 1 desc")
                .photoTitle("photo 1 title")
                .userId("user1")
                .build();
    }

    @GetMapping("/photos/2")
    public Photo photos2() {
        return Photo.builder()
                .photoId("2")
                .photoDescription("photo 2 desc")
                .photoTitle("photo 2 title")
                .userId("user2")
                .build();
    }

    @GetMapping("/photos/3")
    @PreAuthorize("hasAuthority('SCOPE_photo')")
    public Photo photos3() {
        return Photo.builder()
                .photoId("3")
                .photoDescription("photo 3 desc")
                .photoTitle("photo 3 title")
                .userId("user3")
                .build();
    }

    @GetMapping("/photos/custom-role")
    public Photo photos4() {
        return Photo.builder()
                .photoId("4")
                .photoDescription("photo 4 desc")
                .photoTitle("photo 4 title")
                .userId("user4")
                .build();
    }

}
