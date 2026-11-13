package dev.gilberto.gestaousuarios.auditoria;

import jakarta.persistence.*;
import org.springframework.data.domain.Persistable;

import java.time.Instant;
import java.util.UUID;

/**
 * Evento de auditoria de segurança. Sem FK para USUARIOS: o histórico sobrevive à exclusão.
 * O id é atribuído na aplicação; {@link Persistable} evita a consulta prévia do merge no save().
 */
@Entity
@Table(name = "EVENTOS_SEGURANCA", indexes = {
        @Index(name = "IDX_EVENTOS_SEGURANCA_USUARIO", columnList = "USUARIO_ID"),
        @Index(name = "IDX_EVENTOS_SEGURANCA_INSTANTE", columnList = "INSTANTE")
})
public class EventoSeguranca implements Persistable<UUID> {
    @Id
    @Column(name = "ID", nullable = false)
    private UUID id;
    @Enumerated(EnumType.STRING)
    @Column(name = "TIPO", nullable = false, length = 40)
    private TipoEventoSeguranca tipo;
    @Column(name = "USUARIO_ID")
    private UUID usuarioId;
    @Column(name = "INSTANTE", nullable = false)
    private Instant instante;
    @Column(name = "IP", length = 45)
    private String ip;
    @Column(name = "DETALHE", length = 500)
    private String detalhe;

    @Transient
    private boolean novo = true;

    protected EventoSeguranca() {}

    public EventoSeguranca(TipoEventoSeguranca tipo, UUID usuarioId, Instant instante, String ip, String detalhe) {
        this.id = UUID.randomUUID();
        this.tipo = tipo;
        this.usuarioId = usuarioId;
        this.instante = instante;
        this.ip = ip;
        this.detalhe = detalhe;
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return novo;
    }

    @PostPersist
    @PostLoad
    void marcarComoPersistido() {
        this.novo = false;
    }

    public TipoEventoSeguranca getTipo() {
        return tipo;
    }

    public UUID getUsuarioId() {
        return usuarioId;
    }

    public Instant getInstante() {
        return instante;
    }

    public String getIp() {
        return ip;
    }

    public String getDetalhe() {
        return detalhe;
    }
}
