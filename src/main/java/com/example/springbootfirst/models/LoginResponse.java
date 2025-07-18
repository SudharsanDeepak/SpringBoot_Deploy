package com.example.springbootfirst.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Component
public class LoginResponse {
    private String token;
    private String userName;
    private Set<String> roles;
}
