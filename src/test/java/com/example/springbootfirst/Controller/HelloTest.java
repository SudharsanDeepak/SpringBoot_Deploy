package com.example.springbootfirst.Controller;

import com.example.springbootfirst.services.Hello;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HelloTest {



    public void testhellotest()
    {
        Hello hello=new Hello();
        String str=hello.Hellotest();
        System.out.println(str);
        assertEquals("hello",str);
    }

}
