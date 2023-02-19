package ru.zifrkoks.authservice.security.models;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @NotBlank
    @Pattern(regexp = "^(?=.*?[a-z]).{5,32}$")
    private String username;
    @NotBlank
    @Pattern(regexp = "^(?=.*?[a-z])(?=.*?[0-9]).{8,32}$")
    private String password;
    @Email
    private String email;
    @Pattern(regexp = "|^\\+\\d{11,15}")
    private String phone;
}