package ru.zifrkoks.authservice.security.models;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PermissionResponse {
    private String username;
}
