package com.sampson.learnspringsecurity.resouces;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    Logger logger = LoggerFactory.getLogger(getClass());

    private static final List<Todo> TODOS_LIST = List.of(new Todo("flavio","LearnAWS"),new Todo("flavio","Learn Docker"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODOS_LIST;
    }

    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    @PostAuthorize("returnObject.username == 'flavio'")
    @RolesAllowed({"ADMIN","USER"})
    @Secured({"ROLE_ADMIN","ROLE_USER"})
    public Todo retrieveTodosForSpecificUser(@PathVariable String username){
        return TODOS_LIST.get(0);
    }

    @PostMapping ("/users/{username}/todos")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Create {} for {}",todo,username);

    }


}

record Todo(String username,String description){}
