package com.sampson.learnspringsecurity.resouces;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class HelloWorldResource {

    @GetMapping("/hello-world")
    public String helloWorld(){
        return "Hello World";
    }

    @GetMapping("/hello-world-list")
    public List<String> helloWorldList(){
        return List.of("Hello World1","Hello World2","Hello World3");
    }
}
