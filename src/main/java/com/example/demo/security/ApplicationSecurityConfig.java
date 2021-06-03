package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.example.demo.security.ApplicationUserPermissions.COURSE_WRITE;
import static com.example.demo.security.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/v1/students/*").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin() //Form based authentication
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true);


        /*
        HTTP BASIC AUTHENTICATION httpBasic()
        http
                .csrf().disable()
                *//*
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                *//*
                .authorizeRequests()
                //whitelisting patterns /(root url), index page, /css(any css), /js(any js) without basic auth
                .antMatchers("/", "index", "/css/*", "/js/*")
                //permitting all the above whitelisted urls
                .permitAll()
                .antMatchers("/api/v1/students/*").hasRole(STUDENT.name())
                *//*
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers( "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                *//*
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();*/
    }

    @Override
    protected UserDetailsService userDetailsService() {
        UserDetails testUser = User.builder()
                .username("testUser")
                .password(passwordEncoder.encode("password"))
                //.roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUser = User.builder()
                .username("adminUser")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN.name()) // ROLE_ADMIN (ability to read and write for management API)
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails adminTraineeUser = User.builder()
                .username("adminTraineeUser")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN_TRAINEE.name()) // ROLE_ADMIN_TRAINEE (ability to read only for management API)
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(testUser,adminUser,adminTraineeUser);
    }
}
