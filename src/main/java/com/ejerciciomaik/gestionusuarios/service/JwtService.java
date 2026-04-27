package com.ejerciciomaik.gestionusuarios.service;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JwtService {
    /**
     * Inyectamos la clavbe secreta en el service que viene del yaml
     */
    @Value("${security.jwt.secret-key}")
    String secretkey;

    /**
     * Inyectamos la clavew secreta en el service que viene del yaml
     */
    @Value("${security.jwt.token-expiration}")
    Long tokenExpiration;

    /**
     * Transforma la llave secreta DE STRING (base 64) A UN OBJETO SECRETKEY A UNA
     * LIBRERIA
     * 
     * @return firma secreta
     */
    private SecretKey getSignKey() {

        byte[] keyBytes = Decoders.BASE64.decode(secretkey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Genera ekl token de seguridad al iniciar sesion
     * 
     * @param userId
     * @param rolId
     * @param userName
     * @return jwt
     */
    public String generarToken(Long userId, Long rolId, String userName) {
        return Jwts.builder()
                .claims(Map.of("userId", userId))
                .claims(Map.of("rolId", rolId))
                .subject(userName)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .signWith(getSignKey())
                .compact();
    }

    /**
     * verifica si el tokes es valido
     * 
     * @param token
     * @return booleano
     */
    public Boolean isTokenVaild(String token) {
        try {
            // el parser intnetar decifrar la firma del token y los compara
            Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 
     * @param <T>
     * @param token
     * @param resolver
     * @return
     */

    public <T> T extraerClaims(String token, Function<Claims, T> resolver) {
        final Claims claims = Jwts.parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return resolver.apply(claims);
    }

    /**
     * 
     * @param token
     * @retur nombre de ususario
     */
    public String extractUserName(String token) {
        return extraerClaims(token, Claims::getSubject);
    }

    /**
     * Extraer el id del usuario
     * 
     * @param token
     * @return iod del usuario
     */

    public Long extraerUserId(String token) {
        return extraerClaims(token, claims -> claims.get("userId", Long.class));
    }

    /**
     * Extraer el rol del usuario
     * 
     * @param token
     * @return rol del usuario
     */
    public Long extraerRolId(String token) {
        return extraerClaims(token, claims -> claims.get("RolId", Long.class));
    }

    public String refreshToken(String token) throws Exception {
        Claims claims;

        try {
            claims = Jwts.parser()
                    .verifyWith(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new Exception("Token is expired" + e.getMessage());
        } catch (JwtException e) {
            throw new Exception("Token is invalid" + e.getMessage());
        }

        return generarToken(claims.get("userId", Long.class), claims.get("rolId", Long.class), claims.getSubject());
    }
}
