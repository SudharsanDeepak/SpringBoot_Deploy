package com.example.springbootfirst.controllers;

import com.example.springbootfirst.models.Calc;
import com.example.springbootfirst.services.Clacservice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/calc")
public class ClacController {

    @Autowired
    private Clacservice clacservice;


    @GetMapping("/add")
    public int  add(@RequestBody Calc calc)
    {
       return clacservice.add(calc.getA(),calc.getB());
    }
    @GetMapping("/sub")
    public int  sub(@RequestBody Calc calc)
    {
        return clacservice.sub(calc.getA(),calc.getB());
    }
    @GetMapping("/mul")
    public int  mul(@RequestBody Calc calc)
    {
        return clacservice.mul(calc.getA(),calc.getB());
    } @GetMapping("/div")
    public int  div(@RequestBody Calc calc)
    {
        return clacservice.div(calc.getA(),calc.getB());
    }


}
