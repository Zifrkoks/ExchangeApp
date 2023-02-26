package ru.zifrkoks.authservice.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.security.auth.message.AuthException;
import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import ru.zifrkoks.authservice.models.User;
import ru.zifrkoks.authservice.repositories.UserRepository;
import ru.zifrkoks.authservice.security.models.AuthResponse;
import ru.zifrkoks.authservice.security.models.ChangePasswordRequest;
import ru.zifrkoks.authservice.security.models.LoginRequest;
import ru.zifrkoks.authservice.security.models.PermissionResponse;
import ru.zifrkoks.authservice.security.models.RegisterRequest;
import ru.zifrkoks.authservice.security.services.interfaces.AuthService;

@Log4j2
@Service
@RequiredArgsConstructor
public class JwtAuthService implements AuthService {
    @Autowired
    private final UserRepository userRepository;
    @Autowired
    private final PasswordEncoder passwordEncoder;
    @Autowired
    private final JwtTokenProvider jwtTokenProvider;
    @Autowired
    private final AuthenticationManager authenticationManager;

    /**
     * @param request
     * @return
     */
    public AuthResponse signin(LoginRequest request)
    throws AuthException {
        
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            String token = jwtTokenProvider.generateToken(request.getUsername());
            return AuthResponse.builder().token(token).build();
        } catch (Exception e) {
            throw new AuthException("auth error");
        }
    }
    @Transactional
    public AuthResponse signup(RegisterRequest request) 
    throws AuthException{

        if (userRepository.findByUsername(request.getUsername()).isPresent())
            throw new AuthException("user with this name already exists");
        User user = User
            .builder()
            .username(request.getUsername())
            .password(passwordEncoder.encode(request.getPassword()))
            .build();
            try {
                userRepository.save(user);
            } catch (Exception e) {
                throw new AuthException("user is invalid");
            }
            String token = jwtTokenProvider.generateToken(user.getUsername());
            return AuthResponse.builder().token(token).build();
    }
    @Transactional
    public AuthResponse changePassword(String token,ChangePasswordRequest request) 
        throws AuthException{
        try {
            token = jwtTokenProvider.resolveToken(token);
            String username = jwtTokenProvider.getUsername(token);
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("user not found"));
            if(!passwordEncoder.matches(request.getPassword(), user.getPassword()))
                throw new RuntimeException("passwords are different");
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            try {
                userRepository.save(user);
            }
            catch (Exception e){ 
                throw new RuntimeException("validation error");
            }
            try {
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), request.getNewPassword()));
                String newToken = jwtTokenProvider.generateToken(user.getUsername());
                return AuthResponse.builder().token(newToken).build();
            } catch (Exception e) {
                throw new RuntimeException("authentication error");
            }                
        } catch (Exception e) {
            throw new AuthException(e.getMessage());
        }
        
    }

    public PermissionResponse getUsername(String Token) throws AuthException {
        try
        {
            String token = jwtTokenProvider.resolveToken(Token);
            String username = jwtTokenProvider.getUsername(token);
            return PermissionResponse.builder().username(username).build();
        }
        catch(Exception ex){
            throw new AuthException("error");
        }
    }

}
