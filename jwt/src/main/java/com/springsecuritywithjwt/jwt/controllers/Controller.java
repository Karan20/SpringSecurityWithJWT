package com.springsecuritywithjwt.jwt.controllers;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.springsecuritywithjwt.jwt.model.AuthenticationRequest;
import com.springsecuritywithjwt.jwt.model.AuthenticationResponse;
import com.springsecuritywithjwt.jwt.model.MyUserDetailsService;
import com.springsecuritywithjwt.jwt.utilities.JwtUtil;

@RestController
public class Controller {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	
	@Autowired
	private JwtUtil jwtUtil;

	@RequestMapping(value = "/hello", method = RequestMethod.GET)
	public ResponseEntity<?> getHelloWorld() {
		String msg = "Hello World!!!";
		return ResponseEntity.ok(msg);
	}
	
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST )
	public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequest request) throws Exception{
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword(), new ArrayList<>())
					);
		}catch(BadCredentialsException e) {
			throw new Exception("Incorrect username or password", e);
			}
		UserDetails userDetails = myUserDetailsService.loadUserByUsername(request.getUsername());
		 
		String jwt = jwtUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}
	
}
