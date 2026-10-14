package dev.gilberto.gestaousuarios.usuario;

import java.time.Instant;

public record UsuarioResponse(String email, String nome, Instant dataDeCriacao) { }
