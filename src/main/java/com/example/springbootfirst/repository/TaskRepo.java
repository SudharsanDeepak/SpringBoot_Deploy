package com.example.springbootfirst.repository;

import com.example.springbootfirst.models.Tasks;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TaskRepo extends JpaRepository<Tasks,Integer> {

}
