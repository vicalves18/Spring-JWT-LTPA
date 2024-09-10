package br.com.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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
    public String convertJwtToLtpa(@RequestHeader("Authorization") String bearerToken, @RequestParam String username,
        @RequestParam String password) {
        
        String jwtToken = bearerToken.substring(7);
        return authService.convertJwtToLtpa(jwtToken, username, password);
    }
	
	 /*@PostMapping("/convert")
	 public String convertJwtToLtpa(@RequestBody String jwtToken) {
		 return authService.convertJwtToLtpa(jwtToken);
	 }*/
	 
	 @PostMapping("/generatejwt")
	 public ResponseEntity<String> generateJwt(@RequestParam String username) {
		 String token = jwtService.generateJwtToken(username);
	     return ResponseEntity.ok(token);
	 }
	 
	 @PostMapping("/decodeltpa")
	 public Map<String, String> decodeLtpaToken(@RequestBody String ltpaToken) {
		 Map<String, String> decodedParams = authService.decodeLtpaToken(ltpaToken);
	     return decodedParams;
	 }
}
