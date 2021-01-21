package com.auth.api.config;

import com.auth.api.service.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class RequestFilter extends OncePerRequestFilter {
  
  @Autowired
  private JwtUserDetailsService jwtUserDetailsService;
  
  @Autowired
  private JwtTokenUtil jwtTokenUtil;
  
  
  @Override
  protected void doFilterInternal(HttpServletRequest httpServletRequest,
								  HttpServletResponse httpServletResponse,
								  FilterChain filterChain) throws ServletException, IOException {
	
	
	final String requestTokenHeader = httpServletRequest.getHeader("Authorization");
	
	String userName = null;
	String jwtToken = null;
	
	/**
	 *  Remove keyword Bearer from the token
	 *  make sure we wre only process one token per request
	 */
	
	if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
	  jwtToken = requestTokenHeader.substring(7);
	  try {
		userName = jwtTokenUtil.getUserNameFromToken(jwtToken);
	  } catch (IllegalArgumentException e) {
		System.out.println("Unable to parse JWT Token");
	  } catch (ExpiredJwtException ex) {
		System.out.println("JWT Token has expired");
	  }

	} else {
	  System.out.println("Jwt token does not have valid string..");
	}
	
	//Once we get the token validated
	if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
	  UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(userName);
	  /**
	   * if token has valid configuration then will pass it to another api call
	   */
	  if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
		
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
				new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
		usernamePasswordAuthenticationToken
				.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
		
		/**
		 * After verify and pass into next call
		 */
		SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
	  }
	  filterChain.doFilter(httpServletRequest, httpServletResponse);
	}
	
  }
}
