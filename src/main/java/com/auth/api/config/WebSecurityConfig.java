package com.auth.api.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
  
  @Autowired
  private JwtEnteryPoint jwtEnteryPoint;
  
  @Autowired
  private UserDetailsService userDetailsService;
  
  @Autowired
  private RequestFilter requestFilter;
  
  
  @Bean
  public PasswordEncoder passwordEncoder() {
	return new BCryptPasswordEncoder();
  }
  
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
  }
  
  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
	return super.authenticationManagerBean();
  }
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
	
	// We don't need any cookies
	
	http.csrf().disable()
			.authorizeRequests().antMatchers("/authenticate").permitAll()
			//otherwise all the other requests must have token
			.anyRequest().authenticated().and()
			//make sure there is no session
			.exceptionHandling().authenticationEntryPoint(jwtEnteryPoint)
			.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	
	
	// Add the filter
	http.addFilterBefore(requestFilter, UsernamePasswordAuthenticationFilter.class);
	
	
  }
  
  
}
