package io.murad.springsecurity.example.config;

import io.murad.springsecurity.example.security.CSRFTokenLogger;
import io.murad.springsecurity.example.security.StaticKeyAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private StaticKeyAuthenticationFilter filter;

    @Autowired
    private CustomAuthenticationProvider authenticationProvider;

    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private CustomAuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.httpBasic(c->{
//            c.authenticationEntryPoint(new CustomAuthenticationEntryPoint());
//        });
//        http.addFilterBefore(
//                new RequestValidationFilter(),
//                BasicAuthenticationFilter.class)
//                .authorizeRequests()
//                .anyRequest().permitAll();
//    }

//        http.addFilterAt(filter,
//                BasicAuthenticationFilter.class)
//                .authorizeRequests()
//                .anyRequest().permitAll();
//        #CSRFFilter
//        http.addFilterAfter(
//                new CSRFTokenLogger(), CsrfFilter.class)
//                .authorizeRequests()
//                .anyRequest().permitAll();

//        #CORS
//        http.cors(c -> {
//            CorsConfigurationSource source = request -> {
//                CorsConfiguration config = new CorsConfiguration();
//                config.setAllowedOrigins(
//                        List.of("example.com", "example.org"));
//                config.setAllowedMethods(
//                        List.of("GET", "POST", "PUT", "DELETE"));
//                return config;
//            };
//            c.configurationSource(source);
//        });

        http.formLogin()
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .and()
                .httpBasic();
//                .defaultSuccessUrl("/home", true);

        http.authorizeRequests()
//                .mvcMatchers(HttpMethod.GET,"/users").hasAuthority("READ").anyRequest().authenticated();
                .anyRequest().hasAuthority("WRITE");
//        .access("hasAuthority('WRITE')");
//        http.authorizeRequests()
//                .anyRequest().hasRole("ADMIN");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //        auth.inMemoryAuthentication()
//                .withUser("murad")
//                .password(passwordEncoder().encode("admin"))
//                .roles("ADMIN")
//                .authorities("read");
//        Roles and Authories
//        auth.inMemoryAuthentication()
//                .withUser("murad")
//                .password(passwordEncoder().encode("admin"))
//                .roles("ADMIN")
//                .authorities("READ", "WRITE", "DELETE", "UPDATE");
        auth.authenticationProvider(authenticationProvider);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var userDetailsService = new InMemoryUserDetailsManager();

        var user = User.withUsername("murad")
                .password(passwordEncoder().encode("admin"))
                .authorities("READ")
                .build();
        var user2 = User.withUsername("john")
                .password(passwordEncoder().encode("12345"))
                .authorities("WRITE")
                .build();
        userDetailsService.createUser(user);
        userDetailsService.createUser(user2);
        return userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
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
