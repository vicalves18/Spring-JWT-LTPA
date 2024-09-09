package br.com.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.service.AuthService;
import br.com.service.JWTService;

@RestController
@RequestMapping("/auth")
public class AuthController {
	
	@Autowired
	private AuthService authService;
	
	@Autowired
	private JWTService jwtService;
	
	 @PostMapping("/convert")
	 public String convertJwtToLtpa(@RequestBody String jwtToken) {
		 return authService.convertJwtToLtpa(jwtToken);
	 }
	 
	 @PostMapping("/generatejwt")
	 public ResponseEntity<String> generateJwt(@RequestParam String username) {
		 String token = jwtService.generateJwtToken(username);
	     return ResponseEntity.ok(token);
	 }
}
