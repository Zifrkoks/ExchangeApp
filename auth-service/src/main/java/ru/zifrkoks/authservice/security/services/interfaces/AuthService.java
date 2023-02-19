package ru.zifrkoks.authservice.security.services.interfaces;

import jakarta.security.auth.message.AuthException;
import ru.zifrkoks.authservice.security.models.AuthResponse;
import ru.zifrkoks.authservice.security.models.ChangePasswordRequest;
import ru.zifrkoks.authservice.security.models.LoginRequest;
import ru.zifrkoks.authservice.security.models.PermissionResponse;
import ru.zifrkoks.authservice.security.models.RegisterRequest;

public interface AuthService {
    public AuthResponse changePassword (String token,ChangePasswordRequest request) throws AuthException;
    public AuthResponse signin(LoginRequest request) throws AuthException;
    public AuthResponse signup(RegisterRequest request) throws AuthException;
    public PermissionResponse getUsername(String Token) throws AuthException;
}
