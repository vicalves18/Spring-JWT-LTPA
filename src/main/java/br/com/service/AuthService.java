package br.com.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Service
public class AuthService {

	@Value("${jwt.secret}")
	private String jwtSecret;

	@Value("${ltpa.secret}")
	private String ltpaSecret;
	
	private final long ltpaExpiration = 3600000;

	public String convertJwtToLtpa(String jwtToken, String username, String password) {
		Claims claims = Jwts.parser().setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(jwtToken)
				.getBody();

		String jwtUsername = claims.getSubject();
		if (!jwtUsername.equals(username)) {
			throw new IllegalArgumentException("Nome de usuário JWT não corresponde ao nome fornecido.");
		}
		return generateLtpaToken(username, password);
	}

	private String generateLtpaToken(String username, String password) {
		long exp = System.currentTimeMillis() + ltpaExpiration;
	    String params = "username=" + username + "&password=" + password + "&exp=" + exp ;

	    String encodedUserInfo = Base64.getEncoder().encodeToString(params.getBytes(StandardCharsets.UTF_8));

	    String tokenContent = encodedUserInfo + ltpaSecret;

	    String ltpaToken = Base64.getEncoder().encodeToString(tokenContent.getBytes(StandardCharsets.UTF_8));

	    return ltpaToken;
	}

	public Map<String, String> decodeLtpaToken(String ltpaToken) {
	    Map<String, String> values = new HashMap<>();
	    
	    try {
	        String decode = new String(Base64.getDecoder().decode(ltpaToken), StandardCharsets.UTF_8);

	        // Extrai a parte antes do segredo LTPA
	        String conteudo = decode.split(ltpaSecret)[0];

	        // Decodifica novamente para obter o conteúdo original (username e password)
	        String infos = new String(Base64.getDecoder().decode(conteudo), StandardCharsets.UTF_8);

	        // Verifica se a string contém parâmetros
	        if (infos.contains("=") && infos.contains("&")) {
	            String[] params = infos.split("&");
	            for (String param : params) {
	                String[] keyValue = param.split("=");
	                values.put(keyValue[0], keyValue[1]);
	            }
	        } else {
	            System.out.println("Token LTPA não contém os parametros esperados.");
	        }
	    } catch (IllegalArgumentException e) {
	        System.out.println("Erro na descriptografia do token LTPA: " + e.getMessage());
	    }
	    return values;
	}


	/*
	 * public String convertJwtToLtpa(String jwtToken) { try { Claims claims =
	 * Jwts.parser().setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
	 * .parseClaimsJws(jwtToken).getBody();
	 * 
	 * String username = claims.getSubject();
	 * 
	 * return generateLtpaToken(username); } catch (SignatureException e) { throw
	 * new IllegalArgumentException("Token JWT inválido."); } }
	 */

	/*
	 * private String generateLtpaToken(String username) { try { String
	 * ltpaTokenData = "username=" + username;
	 * 
	 * // Crie uma chave secreta para o HMAC SHA-1 Mac mac =
	 * Mac.getInstance("HmacSHA1"); SecretKeySpec secretKeySpec = new
	 * SecretKeySpec(ltpaSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
	 * mac.init(secretKeySpec);
	 * 
	 * byte[] signature =
	 * mac.doFinal(ltpaTokenData.getBytes(StandardCharsets.UTF_8)); byte[] ltpaToken
	 * = Base64 .encodeBase64((ltpaTokenData + ":" + new
	 * String(signature)).getBytes(StandardCharsets.UTF_8));
	 * 
	 * return new String(ltpaToken); } catch (Exception e) { throw new
	 * RuntimeException("Erro ao gerar token LTPA", e); } }
	 */
}
