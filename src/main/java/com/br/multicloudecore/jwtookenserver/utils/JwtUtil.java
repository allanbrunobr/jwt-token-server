package com.br.multicloudecore.jwtookenserver.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {
    private final SecretKey secretKey;
    private final long expiration;

    public JwtUtil(@Value("${jwt.secret}") String secret, @Value("${jwt.expiration}") long expiration) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.expiration = expiration;
    }

    public String generateToken(String username, String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration * 1000);

        Map<String, Object> claims = new HashMap<>();
        claims.put("username", username);
        claims.put("email", email);

        return Jwts.builder().claims(claims).subject(username).issuedAt(now).expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
        return claims.getSubject();
    }
}
