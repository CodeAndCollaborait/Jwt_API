package com.auth.api.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {
  
  @Override
  public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
	
    if ("javacollab".equals(userName)){
      return new User("javacollab", "$2a$10$aKS8kvqcX3tlsbPR1tfQeuiwrTDBxsm8Cy8slFjt3/lYWv4bWNvkS",
			  new ArrayList<>());
	}else {
      throw new UsernameNotFoundException("User not found with username of: " + userName);
	}
  }
}
