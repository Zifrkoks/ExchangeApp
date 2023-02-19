package ru.zifrkoks.authservice.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import ru.zifrkoks.authservice.models.User;

public interface UserRepository extends CrudRepository<User, Integer>{
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByPhoneNumber(String phoneNumber);

}
