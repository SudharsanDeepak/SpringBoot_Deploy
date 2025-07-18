package com.example.springbootfirst.jwt;


import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider{

    @Value("${app.jwt-secret}")
    private String jwtSecret;

    @Value("${app.jwt-expiration-milliseconds}")
    private    long jwtExpirationData;

    public String generateToken(Authentication authenticate) {
        UserDetails userprincipal = (UserDetails) authenticate
                                    .getPrincipal();

        return Jwts.builder()
                .setSubject(userprincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+   jwtExpirationData))
                .signWith(Secretkey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getuserNameFromToken(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(Secretkey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token) {

        try{
            Jwts.parserBuilder()
                    .setSigningKey(Secretkey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        }
        catch (JwtException jwtException){
            jwtException.printStackTrace();

        }
        return false;

    }

    public String getUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Secretkey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    private Key Secretkey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }


}
