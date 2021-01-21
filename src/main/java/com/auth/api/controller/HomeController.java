package com.auth.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
  
  
  @GetMapping("/hello")
  public String welcomePage(){
    return "Welcome to Auth API";
  }
}
