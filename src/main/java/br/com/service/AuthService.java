package br.com.service;

import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

@Service
public class AuthService {
	
	@Value("${jwt.secret}")
	private String jwtSecret;
	
	@Value("${ltpa.secret}")
	private String ltpaSecret;
	
	
	public String convertJwtToLtpa(String jwtToken) {
        try {
            Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(jwtToken)
                .getBody();

            String username = claims.getSubject();
            
            return generateLtpaToken(username);
        } catch (SignatureException e) {
            throw new IllegalArgumentException("Token JWT inválido.");
        }
    }

    private String generateLtpaToken(String username) {
        try {
            String ltpaTokenData = "username=" + username;

            // Crie uma chave secreta para o HMAC SHA-1
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec secretKeySpec = new SecretKeySpec(ltpaSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
            mac.init(secretKeySpec);

            byte[] signature = mac.doFinal(ltpaTokenData.getBytes(StandardCharsets.UTF_8));
            byte[] ltpaToken = Base64.encodeBase64((ltpaTokenData + ":" + new String(signature)).getBytes(StandardCharsets.UTF_8));

            return new String(ltpaToken);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar token LTPA", e);
        }
    }
}
