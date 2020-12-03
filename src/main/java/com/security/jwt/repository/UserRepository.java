package com.security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.jwt.entity.Usuario;

public interface UserRepository extends JpaRepository<Usuario, Long>{

	Usuario findByEmail(String email);
	boolean existsByEmail(String email);
}
