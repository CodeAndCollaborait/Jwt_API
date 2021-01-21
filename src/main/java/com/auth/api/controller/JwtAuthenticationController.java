package com.auth.api.controller;

import com.auth.api.config.JwtTokenUtil;
import com.auth.api.model.JwtRequestModel;
import com.auth.api.model.JwtResponse;
import com.auth.api.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
public class JwtAuthenticationController {
  
  @Autowired
  private AuthenticationManager authenticationManager;
  
  @Autowired
  private JwtTokenUtil jwtTokenUtil;
  
  @Autowired
  private JwtUserDetailsService userDetailsService;
  
  
   @PostMapping("/authenticate")
  public ResponseEntity<?> createAuthToken(@RequestBody JwtRequestModel authRequest) throws Exception{
    
    authenticateMethod(authRequest.getUserName(), authRequest.getPassword());
    
    final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUserName());
    
    final String token = jwtTokenUtil.generateToken(userDetails);
    
    return ResponseEntity.ok(new JwtResponse(token));
    
   }
  
  
  private void authenticateMethod(String userName, String password) throws Exception{
    try {
         authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName, password));
    }catch (DisabledException e){
      throw new Exception("User_Disabled", e);
    }catch (BadCredentialsException e){
        throw new Exception("Invalid Exception", e);
    }
  }
  
  
}
