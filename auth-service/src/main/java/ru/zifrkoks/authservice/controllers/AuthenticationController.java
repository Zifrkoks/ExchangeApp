package ru.zifrkoks.authservice.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.security.auth.message.AuthException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import ru.zifrkoks.authservice.security.models.AppError;
import ru.zifrkoks.authservice.security.models.AuthResponse;
import ru.zifrkoks.authservice.security.models.ChangePasswordRequest;
import ru.zifrkoks.authservice.security.models.LoginRequest;
import ru.zifrkoks.authservice.security.models.PermissionResponse;
import ru.zifrkoks.authservice.security.models.RegisterRequest;
import ru.zifrkoks.authservice.security.services.interfaces.AuthService;

@Log4j2
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
  @Autowired
  private AuthService service;

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException e) {
    
    Map<String, String> errors = new HashMap<>();
    e.getBindingResult().getAllErrors().forEach((error) -> {
        String fieldName = ((FieldError) error).getField();
        String errorMessage = error.getDefaultMessage();
        errors.put(fieldName, errorMessage);
    });
    log.error(errors);
    return errors;
    
  }

  @ExceptionHandler(AuthException.class)
  public ResponseEntity<AppError> catchException(AuthException e) {
    log.error(e.getMessage(), e);
    return new ResponseEntity<>(new AppError(e.getMessage()),HttpStatus.BAD_REQUEST);
  }
  @PostMapping("/signup")
  public AuthResponse register
  (@Valid @RequestBody RegisterRequest request) throws AuthException {
  
    return service.signup(request);
  }
  @PostMapping("/signin")
  public AuthResponse authenticate(@RequestBody LoginRequest request) throws AuthException {
      return service.signin(request);
  }
  @PostMapping("/changepassword")
  public AuthResponse changePassword(
  @RequestHeader("Authorization") String token
  ,@RequestBody ChangePasswordRequest request) throws AuthException
  {
    return service.changePassword(token,request);
  }

  @GetMapping("/username")
  public PermissionResponse getUsername(@RequestHeader("Authorization") String token) throws AuthException{
    return service.getUsername(token);
  } 
}
