package com.example.springbootfirst.Controller;

import com.example.springbootfirst.models.Calc;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Calctezt {

        Calc calc1=new Calc();

        public void addtest()
        {
            int a=2,b=2;
            calc1.setA(a);
            calc1.setB(b);
            assertEquals(a+b,calc1.getA()+calc1.getB());
        }
        public void subtest()
        {
            int a=2,b=2;
            calc1.setA(a);
            calc1.setB(b);
            assertEquals(a-b,calc1.getA()-calc1.getB());
        }
        public void multest()
        {
            int a=2,b=2;
            calc1.setA(a);
            calc1.setB(b);
            assertEquals(a*b,calc1.getA()*calc1.getB());
        }
        public void divtest()
        {
            int a=2,b=2;
            calc1.setA(a);
            calc1.setB(b);
            assertEquals(a/b,calc1.getA()/calc1.getB());
        }




}
