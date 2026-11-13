package dev.gilberto.gestaousuarios.auth;

import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public class JpaRefreshTokenStore implements RefreshTokenStore {
    private final RefreshTokenRepository repository;

    public JpaRefreshTokenStore(RefreshTokenRepository repository) {
        this.repository = repository;
    }

    @Override
    public RefreshToken salvar(RefreshToken token) {
        return repository.save(token);
    }

    @Override
    public Optional<RefreshToken> buscarPorHash(String hash) {
        return repository.findByTokenHash(hash);
    }

    @Override
    public int consumirSeAtivo(UUID id, Instant agora, UUID substitutoId) {
        return repository.consumirSeAtivo(id, agora, substitutoId, MotivoRevogacao.ROTACAO);
    }

    @Override
    public int revogarFamilia(UUID familiaId, Instant agora, MotivoRevogacao motivo) {
        return repository.revogarFamilia(familiaId, agora, motivo);
    }

    @Override
    public int revogarTodosDoUsuario(UUID usuarioId, Instant agora, MotivoRevogacao motivo) {
        return repository.revogarTodosDoUsuario(usuarioId, agora, motivo);
    }

    @Override
    public int removerTodosDoUsuario(UUID usuarioId) {
        return repository.removerTodosDoUsuario(usuarioId);
    }
}
