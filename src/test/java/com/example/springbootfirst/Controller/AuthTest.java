package com.example.springbootfirst.Controller;

import com.example.springbootfirst.controllers.AuthController;
import com.example.springbootfirst.models.RegisterDetails;
import com.example.springbootfirst.models.UserDetailsDto;
import com.example.springbootfirst.services.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

public class AuthTest {
    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    @BeforeEach
    public void init(){
        MockitoAnnotations.initMocks(this);
    }

    @Test
    void AddUertest()
    {
        UserDetailsDto dto = new UserDetailsDto();

        dto.setName("sharan");
        dto.setPassword("pass123");
        dto.setUserName("sharan06");
        dto.setEmail("sharan06@gmail.com");
        Set<String> roleNames = new HashSet<>();
        roleNames.add("ROLE_USER");
        roleNames.add("ROLE_ADMIN");
        dto.setRoleNames(roleNames);

        when(authService.addNewEmployee(dto)).thenReturn("Added Employee");
        String result = authController.addNewUser(dto);
        assertEquals("User Registered", result);
    }

//    @Test
//    void loginUsertest()
//    {
//        RegisterDetails reg = new RegisterDetails();
//        reg.setUserName("sharan06");
//        reg.setPassword("pass123");
////        when(authService.authenticateAndGenerateToken("sharan", "password123"))
////                .thenReturn("login done");
//
//        String result = authController.Login(reg);
//        assertEquals("login done", result);
//    }
}
