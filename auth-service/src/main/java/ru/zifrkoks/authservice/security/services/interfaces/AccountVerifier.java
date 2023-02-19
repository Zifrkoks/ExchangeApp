package ru.zifrkoks.authservice.security.services.interfaces;

import ru.zifrkoks.authservice.models.User;

public interface AccountVerifier {
    public void sendVerificationLink(User user);
}
