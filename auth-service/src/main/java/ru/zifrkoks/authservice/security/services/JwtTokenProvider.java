package ru.zifrkoks.authservice.security.services;

import java.security.Key;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.security.auth.message.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.log4j.Log4j2;


@Log4j2
public class JwtTokenProvider {
    @Value("${secretKey}")
    private String SECRET_KEY;
    private UserDetailsService userdDetailsService;
    
    /**
     * @param userdDetailsService
     */
    public JwtTokenProvider(UserDetailsService userdDetailsService) {
        this.userdDetailsService = userdDetailsService;
    }
    public String generateToken(String username) {
        return generateToken(new HashMap<>(), username);
    }
    public Authentication getAuthentication(String token)
    throws UsernameNotFoundException {
        try {
            UserDetails userDetails = userdDetailsService.loadUserByUsername(getUsername(token));
            return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
        } catch (Exception e) {
            throw new UsernameNotFoundException("user not found");
        }
        
    }

    public String getUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody().getSubject();
    }
    public String generateToken(Map<String, Object> extraClaims,String username)
    {

        return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(username)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plus(3, ChronoUnit.DAYS)))
            .signWith(getSignInKey())
            .compact();
    }
    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String resolveToken(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return null;
    }
    public boolean validateToken(String token) throws AuthException {
        try {
            Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            throw new AuthException("Invalid JWT signature: {}");
        } catch (MalformedJwtException e) {
            throw new AuthException("Invalid JWT token: {}");
        } catch (ExpiredJwtException e) {
            throw new AuthException("JWT token is expired: {}");
        } catch (UnsupportedJwtException e) {
            throw new AuthException("JWT token is unsupported: {}");
        } catch (IllegalArgumentException e) {
            throw new AuthException("JWT claims string is empty: {}");
        }
    }


    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // return Keys.hmacShaKeyFor(keyBytes);
        return new SecretKeySpec(Base64.getDecoder().decode(SECRET_KEY), 
        SignatureAlgorithm.HS256.getJcaName()); 
    }
    
}