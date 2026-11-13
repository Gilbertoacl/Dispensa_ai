package dev.gilberto.gestaousuarios.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /** Rotação atômica: o número de linhas afetadas (0 ou 1) decide quem venceu a corrida. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            update RefreshToken t
               set t.revogadoEm = :agora, t.motivoRevogacao = :motivo, t.substituidoPorId = :novoId
             where t.id = :id and t.revogadoEm is null and t.expiraEm > :agora""")
    int consumirSeAtivo(@Param("id") UUID id, @Param("agora") Instant agora,
                        @Param("novoId") UUID novoId, @Param("motivo") MotivoRevogacao motivo);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revogadoEm = :agora, t.motivoRevogacao = :motivo "
            + "where t.familiaId = :familiaId and t.revogadoEm is null")
    int revogarFamilia(@Param("familiaId") UUID familiaId, @Param("agora") Instant agora,
                       @Param("motivo") MotivoRevogacao motivo);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revogadoEm = :agora, t.motivoRevogacao = :motivo "
            + "where t.usuarioId = :usuarioId and t.revogadoEm is null")
    int revogarTodosDoUsuario(@Param("usuarioId") UUID usuarioId, @Param("agora") Instant agora,
                              @Param("motivo") MotivoRevogacao motivo);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.usuarioId = :usuarioId")
    int removerTodosDoUsuario(@Param("usuarioId") UUID usuarioId);
}
