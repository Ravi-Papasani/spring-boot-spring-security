package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.security.ApplicationUserRoles.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDAO{

    private final PasswordEncoder passwordEncoder;
    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser("testUser", passwordEncoder.encode("password"), STUDENT.getGrantedAuthorities(),true,true,true,true),
                new ApplicationUser("adminUser", passwordEncoder.encode("password123"), ADMIN.getGrantedAuthorities(),true,true,true,true),
                new ApplicationUser("adminTraineeUser", passwordEncoder.encode("password123"), ADMIN_TRAINEE.getGrantedAuthorities(),true,true,true,true)
        );
        return applicationUsers;
    }
}