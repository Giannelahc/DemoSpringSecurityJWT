package com.security.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.jwt.entity.Usuario;
import com.security.jwt.service.UsuarioService;

@RestController
@RequestMapping("/user")
public class UsuarioController {

	@Autowired
	private UsuarioService usuarioService;
	
	@PostMapping("/register")
	public ResponseEntity<?> register(@RequestBody Usuario usuario){
		
		if(usuarioService.register(usuario) == null) {
			return ResponseEntity.badRequest().body("ERROR AL CREAR EL USUARIO");
		}
		return ResponseEntity.ok(usuario);
	}
	
	@GetMapping("/lista")
	public ResponseEntity<?> listar(){
		return ResponseEntity.ok("listado");
	}
}
