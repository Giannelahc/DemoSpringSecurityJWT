package com.security.jwt.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.security.jwt.entity.Role;
import com.security.jwt.entity.Usuario;
import com.security.jwt.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		Usuario user = userRepository.findByEmail(email);
		
		if(user == null) {
        	//logger.error("Error en el Login: no existe el usuario '" + email + "' en el sistema!");
        	throw new UsernameNotFoundException("Username: " + email + " no existe en el sistema!");
        }
        
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        
        for(Role role: user.getRoles()) {
        	//logger.info("Role: ".concat(role.getAuthority()));
        	authorities.add(new SimpleGrantedAuthority(role.getAuthority()));
        }
        
        if(authorities.isEmpty()) {
        	//logger.error("Error en el Login: Usuario '" + username + "' no tiene roles asignados!");
        	throw new UsernameNotFoundException("Error en el Login: usuario '" + email + "' no tiene roles asignados!");
        }
        
		return new User(user.getEmail(), user.getPassword(), user.getEnabled(), true, true, true, authorities);
	}

}
