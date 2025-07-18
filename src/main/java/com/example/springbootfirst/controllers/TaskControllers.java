package com.example.springbootfirst.controllers;


import com.example.springbootfirst.models.Tasks;
import com.example.springbootfirst.services.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.config.Task;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@CrossOrigin
@RestController

public class TaskControllers {


    @Autowired
    private TaskService taskService;
    @PostMapping("/addtask")

    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    public void AddTask(@RequestBody Tasks task){
        taskService.addtask(task);
    }

    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    @GetMapping("/tasks")
    public List<Tasks> findAlltask(){
        return taskService.findall();
    }

    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    @GetMapping("/tasks/{id}")
    public Optional<Tasks>findByIdtask(@PathVariable int id){
        return taskService.findallbyid(id);
    }

    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    @DeleteMapping("task/{id}")
    public void deletetask(@PathVariable int id){
        taskService.deleteById(id);
    }

}
