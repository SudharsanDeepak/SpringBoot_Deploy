package com.example.springbootfirst.Controller;

import com.example.springbootfirst.controllers.EmployeeController;
import com.example.springbootfirst.models.RegisterDetails;
import com.example.springbootfirst.services.EmployeeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

public class EmployeeControllerTest {

        @Mock
        EmployeeService employeeService;
        @InjectMocks
        EmployeeController employeeController;

        @BeforeEach
        public void init(){
            MockitoAnnotations.initMocks(this);
        }
        @Test
        void tesRoute()
        {
            String str=employeeController.route();
            assertEquals("Welcome to SpringBoot Security",str);
        }
        @Test
        void testGetMethod(){
            RegisterDetails emp1=new RegisterDetails();
            RegisterDetails emp2=new RegisterDetails();

            when(employeeService.getMethod()).thenReturn(Arrays.asList(emp1,emp2));
            List<RegisterDetails> result=employeeController.getMethod();
            assertEquals(2,result.size());
        }

        @Test
        void testEmpbyid(){
            RegisterDetails emp1=new RegisterDetails();
            emp1.setEmpId(1);
            when(employeeService.getEmployeeById(1)).thenReturn(emp1);
            RegisterDetails result = employeeController.getEmployeeById(1);
            assertEquals(1,result.getEmpId());
        }

        @Test
        void testput(){
        when(employeeService.updateEmployee(1)).thenReturn("Employee upadtedone");

        String result = employeeController.putMethod(1);
        assertEquals("Employee upadtedone", result);
        }

        @Test
        void delete(){
            when(employeeService.deleteEmployeeById(1)).thenReturn("Employee deletedone");
            String result = employeeController.deleteMethod(1);
            assertEquals("Employee deletedone", result);
        }


}
