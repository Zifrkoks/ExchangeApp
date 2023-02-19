package ru.zifrkoks.authservice.security.filters;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import ru.zifrkoks.authservice.security.services.JwtTokenProvider;

public class JwtAuthFilterConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>  {
    private JwtTokenProvider jwtTokenProvider;

  public JwtAuthFilterConfigurer(JwtTokenProvider jwtTokenProvider) {
    this.jwtTokenProvider = jwtTokenProvider;
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    JwtAuthFilter customFilter = new JwtAuthFilter(jwtTokenProvider);
    http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
  }
}
