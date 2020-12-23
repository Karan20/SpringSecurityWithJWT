package com.springsecuritywithjwt.jwt.utilities;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtil {

	
	@Value("${jwt.secretkey}")
	private String secretKey;
	
	@Value("${jwt.timeout}")
	private Long timeout;
	
	private String createToken(Map<String,Object> claims, String username) {
		return Jwts.builder().setClaims(claims).setIssuedAt(new Date(System.currentTimeMillis()))
				.setSubject(username).setExpiration(new Date(System.currentTimeMillis()+ timeout))
				.signWith(SignatureAlgorithm.HS256, secretKey).compact();
	}
	
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<String, Object>();
		return createToken(claims, userDetails.getUsername());
	}
	
	public Date extractExpirationTime(String token) {
		return extractClaims(token, Claims::getExpiration);
	}
	
	public String extractUsername(String token) {
		return extractClaims(token, Claims::getSubject);
	}
	
	public Boolean isTokenExpired(String token) {
		return extractClaims(token, Claims::getExpiration).before(new Date(System.currentTimeMillis()));
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
	}
	
	private <R> R extractClaims(String token, Function<Claims, R> claimsResolver) {
		Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	public Boolean isTokenValid(String token, UserDetails userDetails) {
		return (userDetails.getUsername().equalsIgnoreCase(extractUsername(token))
				&& !isTokenExpired(token));
	}
}
