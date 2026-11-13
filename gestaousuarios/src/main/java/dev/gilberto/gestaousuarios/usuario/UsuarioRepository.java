package dev.gilberto.gestaousuarios.usuario;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, UUID> {
    boolean existsByEmail(String email);

    Optional<Usuario> findByEmail(String email);

    @Transactional(readOnly = true)
    @Query("select u.tokenVersion from Usuario u where u.id = :id")
    Optional<Integer> buscarTokenVersion(UUID id);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update Usuario u set u.tokenVersion = u.tokenVersion + 1 where u.id = :id")
    int incrementarTokenVersion(UUID id);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update Usuario u set u.ultimoLoginEm = :instante where u.id = :id")
    int registrarUltimoLogin(UUID id, Instant instante);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from Usuario u where u.perfil = :perfil order by u.id")
    List<Usuario> travarPorPerfil(Perfil perfil);
}
