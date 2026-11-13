package dev.gilberto.gestaousuarios.usuario;

import java.time.Instant;
import java.util.UUID;

/**
 * Evento de domínio publicado quando um {@link Usuario} é criado (R16).
 *
 * <p>Nomeado como fato ocorrido no passado (R16.2) e com contrato próprio. Carrega o
 * identificador, o email e a data de criação do usuário (R16.1).</p>
 */
public record UsuarioCriadoEvent(UUID id, String email, Instant dataCriacao) {
}
