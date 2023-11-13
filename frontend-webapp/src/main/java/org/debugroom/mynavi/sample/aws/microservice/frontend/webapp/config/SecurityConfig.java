package org.debugroom.mynavi.sample.aws.microservice.frontend.webapp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.debugroom.mynavi.sample.aws.microservice.frontend.webapp.app.web.security.LoginSuccessHandler;
import org.debugroom.mynavi.sample.aws.microservice.frontend.webapp.app.web.security.SessionExpiredDetectingLoginUrlAuthenticationEntryPoint;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

	@Autowired
	@Lazy
	PasswordEncoder passwordEncoder;

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring().requestMatchers("/static/**");
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(
				authz -> authz.requestMatchers("/favicon.ico").permitAll()
							.requestMatchers("/webjars/**").permitAll()
							.requestMatchers("/static/**").permitAll()
							.requestMatchers("/timeout").permitAll()
							.anyRequest().authenticated())
		.csrf(csrf -> csrf.disable())
		.formLogin(login -> login.loginProcessingUrl("/authenticate")
								.loginPage("/login")
								.successHandler(loginSuccessHandler())
								.failureUrl("/login")
								.usernameParameter("username")
								.passwordParameter("password").permitAll())
		.exceptionHandling(eh -> eh.authenticationEntryPoint(authenticationEntryPoint()))
		.logout(logout -> logout.logoutSuccessUrl("/login"));
		return http.build();
	}

	@Bean
	public LoginSuccessHandler loginSuccessHandler() {
		return new LoginSuccessHandler();
	}

	@Bean
	AuthenticationEntryPoint authenticationEntryPoint() {
		return new SessionExpiredDetectingLoginUrlAuthenticationEntryPoint("/login");
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

}
