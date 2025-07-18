package com.example.springbootfirst.controllers;

import com.example.springbootfirst.models.LoginResponse;
import com.example.springbootfirst.models.RegisterDetails;
import com.example.springbootfirst.models.UserDetailsDto;
import com.example.springbootfirst.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin
public class AuthController {

    @Autowired
    AuthService authService;


    @PostMapping("/register")
    public String addNewUser(@RequestBody UserDetailsDto register){
        System.out.println(register);
        return authService.addNewEmployee(register);
    }

    @PostMapping("/login")
    public LoginResponse Login(@RequestBody RegisterDetails login){
        System.out.println(login.getName()+login.getPassword());

        return authService.authenticateAndGenerateToken(login.getName(), login.getPassword());
    }

}
