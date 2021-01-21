package com.auth.api.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil implements Serializable {
  
  //TODO
  public static final long JWT_TOKEN_VALID = 5 * 60 * 60;
  
  //1. Set Secret set
  @Value("${jwt.secret}")
  private String secret;
  
  // For getting any information from token and so we need sceret key??
  public Claims getAllClaimsFromToken(String token) {
	return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
  }
  
  //return get all the information from token with
  public <T> T getClaimFromToken(String token, Function<Claims, T> claimsTFunction) {
	final Claims claims = getAllClaimsFromToken(token);
	return claimsTFunction.apply(claims);
  }
  
  //2. Get the username
  public String getUserNameFromToken(String token) {
	return getClaimFromToken(token, Claims::getSubject);
  }
  
  //3. Token key is expired or not
  public Date getExpirationDateFromToken(String token) {
	return getClaimFromToken(token, Claims::getExpiration);
  }
  
  //4. Check if token data is before current date.  (return true or false)
  private Boolean isTokenExpired(String token) {
	final Date expiration = getExpirationDateFromToken(token);
	return expiration.before(new Date());
  }
  
  //5. Generate new Token;
  public String generateToken(UserDetails userDetails) {
	Map<String, Object> claims = new HashMap<>();
	return generateToken(claims, userDetails.getUsername());
  }
  
  //6. How to generate token
  
  /**
   * 1. Define the claims ob of token, Expiration date, sub and ect
   * 2. Assign the algorithm for the token HS512 and secret key
   * 3. provide into serialization
   */
  
  private String generateToken(Map<String, Object> claims, String subject) {
	return Jwts.builder()
			.setClaims(claims)
            .setSubject(subject)
			.setIssuedAt(new Date(System.currentTimeMillis()))
			.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALID * 1000))
			.signWith(SignatureAlgorithm.HS512, secret).compact();
  }
  
  
  //7. How to verify the token
  public Boolean validateToken(String token, UserDetails userDetails) {
	final String userName = getUserNameFromToken(token);
	return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }
  
  
}
