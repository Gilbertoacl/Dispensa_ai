package dev.gilberto.gestaousuarios.auditoria;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface EventoSegurancaRepository extends JpaRepository<EventoSeguranca, UUID> {
}
