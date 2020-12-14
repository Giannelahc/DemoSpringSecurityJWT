package com.security.jwt.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.security.jwt.auth.service.JWTService;
import com.security.jwt.auth.service.impl.JWTServiceImpl;


public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(JWTAuthorizationFilter.class);
	
	private JWTService jwtService;
	
	private UserDetailsService userDetailsService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService, UserDetailsService userDetailsService) {
		super(authenticationManager);
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}
	
	//Pasa el filtro de autorizacion despues del filtro de autenticacion
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		
		String header = request.getHeader(JWTServiceImpl.HEADER_STRING);
		
		//si el token es existe
		if(!requiresAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}
		
		//***** Tambien puede cargarse el username y authorities con userDetailsService******
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(jwtService.getUsername(header));
		
		UsernamePasswordAuthenticationToken authentication = null;
		
		//si el token es valido crea el usuario 
		if(jwtService.validate(header)) {
			//authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header),null,jwtService.getRoles(header));
			authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
		}
		LOG.info(authentication.toString());
		LOG.info(jwtService.validate(header)+"");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request,response);
	}
	
	protected boolean requiresAuthentication(String header) {
		if(header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX))
			return false;
		return true;
	}
}
