package com.security.jwt.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.security.jwt.entity.Usuario;
import com.security.jwt.repository.UserRepository;
import com.security.jwt.service.UsuarioService;

@Service
public class UsuarioServiceImpl implements UsuarioService{

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Override
	public Usuario register(Usuario usuario) {
		if(!userRepository.existsByEmail(usuario.getEmail())) {
			usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
			return userRepository.save(usuario);
		}
		return null;
	}

}
