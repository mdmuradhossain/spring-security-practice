package io.murad.springsecurity.example.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationProvider authenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.httpBasic(c->{
//            c.authenticationEntryPoint(new CustomAuthenticationEntryPoint());
//        });
        http.formLogin()
                .defaultSuccessUrl("/home",true);
        http.authorizeRequests()
                .anyRequest()
                .authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //        auth.inMemoryAuthentication()
//                .withUser("murad")
//                .password(passwordEncoder().encode("admin"))
//                .roles("ADMIN")
//                .authorities("read");
        auth.authenticationProvider(authenticationProvider);
    }

    //    @Bean
//    public UserDetailsService userDetailsService() {
//        var userDetailsService = new InMemoryUserDetailsManager();
//
//        var user = User.withUsername("murad")
//                .password(passwordEncoder().encode("admin"))
//                .authorities("read")
//                .build();
//        userDetailsService.createUser(user);
//        return userDetailsService;
//    }

    /*
    * For using multiple hashing Algorithm
     */
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        Map<String, PasswordEncoder> encoders = new HashMap<>();
//        encoders.put("noop", NoOpPasswordEncoder.getInstance());
//        encoders.put("bcrypt", new BCryptPasswordEncoder());
//        encoders.put("scrypt", new SCryptPasswordEncoder());
//        return new DelegatingPasswordEncoder("bcrypt", encoders);
//    }

}
