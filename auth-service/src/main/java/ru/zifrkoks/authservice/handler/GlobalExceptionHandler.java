package ru.zifrkoks.authservice.handler;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import jakarta.security.auth.message.AuthException;
import lombok.extern.slf4j.Slf4j;
import ru.zifrkoks.authservice.security.models.AppError;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    @ExceptionHandler
    public ResponseEntity<AppError> catchException(AuthException e) {
        log.error(e.getMessage(), e);
        return new ResponseEntity<>(new AppError(e.getMessage()),HttpStatus.BAD_REQUEST);
    }
}
