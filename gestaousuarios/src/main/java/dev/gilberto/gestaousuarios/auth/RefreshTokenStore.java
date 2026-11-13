package dev.gilberto.gestaousuarios.auth;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Porta de persistência de refresh tokens. Permite testar o SessaoService com um fake em memória.
 */
public interface RefreshTokenStore {

    RefreshToken salvar(RefreshToken token);

    Optional<RefreshToken> buscarPorHash(String hash);

    /** Revoga com motivo ROTACAO se ativo; devolve 1 se consumiu e 0 se perdeu a corrida. */
    int consumirSeAtivo(UUID id, Instant agora, UUID substitutoId);

    int revogarFamilia(UUID familiaId, Instant agora, MotivoRevogacao motivo);

    int revogarTodosDoUsuario(UUID usuarioId, Instant agora, MotivoRevogacao motivo);

    int removerTodosDoUsuario(UUID usuarioId);
}
