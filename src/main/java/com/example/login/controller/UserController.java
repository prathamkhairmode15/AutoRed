package com.example.login.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("/me")
    public Map<String, String> me(Authentication authentication) {
        String userId = authentication != null ? authentication.getName() : null;
        return Map.of("userId", userId != null ? userId : "");
    }
}
