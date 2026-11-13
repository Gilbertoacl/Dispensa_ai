package dev.gilberto.gestaousuarios.usuario;

import java.time.Instant;
import java.util.UUID;

public record UsuarioResponse(UUID id, String email, String nome, Perfil perfil, Instant dataDeCriacao) { }
