package dev.gilberto.gestaousuarios.auth;

import jakarta.persistence.*;
import org.springframework.data.domain.Persistable;

import java.time.Instant;
import java.util.UUID;

/**
 * Refresh token opaco. Somente o hash SHA-256 é persistido. O id é atribuído na aplicação;
 * {@link Persistable} evita a consulta prévia do merge no save(). {@code usuarioId} é um UUID simples
 * (sem associação) para que o pacote auth não dependa da entidade de outro agregado.
 */
@Entity
@Table(name = "REFRESH_TOKENS", indexes = {
        @Index(name = "IDX_REFRESH_TOKENS_USUARIO", columnList = "USUARIO_ID"),
        @Index(name = "IDX_REFRESH_TOKENS_FAMILIA", columnList = "FAMILIA_ID")
}, uniqueConstraints = @UniqueConstraint(name = "UK_REFRESH_TOKENS_HASH", columnNames = "TOKEN_HASH"))
public class RefreshToken implements Persistable<UUID> {
    static final int USER_AGENT_MAX = 255;

    @Id
    @Column(name = "ID", nullable = false)
    private UUID id;
    @Column(name = "USUARIO_ID", nullable = false)
    private UUID usuarioId;
    @Column(name = "TOKEN_HASH", nullable = false, length = 64)
    private String tokenHash;
    @Column(name = "FAMILIA_ID", nullable = false)
    private UUID familiaId;
    @Column(name = "EXPIRA_EM", nullable = false)
    private Instant expiraEm;
    @Column(name = "REVOGADO_EM")
    private Instant revogadoEm;
    @Enumerated(EnumType.STRING)
    @Column(name = "MOTIVO_REVOGACAO", length = 30)
    private MotivoRevogacao motivoRevogacao;
    @Column(name = "SUBSTITUIDO_POR_ID")
    private UUID substituidoPorId;
    @Column(name = "CRIADO_EM", nullable = false)
    private Instant criadoEm;
    @Column(name = "USER_AGENT", length = USER_AGENT_MAX)
    private String userAgent;
    @Column(name = "IP", length = 45)
    private String ip;

    @Transient
    private boolean novo = true;

    protected RefreshToken() {}

    public RefreshToken(UUID id, UUID usuarioId, String tokenHash, UUID familiaId, Instant criadoEm,
                        Instant expiraEm, String userAgent, String ip) {
        this.id = id;
        this.usuarioId = usuarioId;
        this.tokenHash = tokenHash;
        this.familiaId = familiaId;
        this.criadoEm = criadoEm;
        this.expiraEm = expiraEm;
        this.userAgent = userAgent != null && userAgent.length() > USER_AGENT_MAX
                ? userAgent.substring(0, USER_AGENT_MAX) : userAgent;
        this.ip = ip;
    }

    /** Ativo: não revogado e com expiração estritamente posterior ao instante. */
    public boolean ativoEm(Instant agora) {
        return revogadoEm == null && expiraEm.isAfter(agora);
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

    public UUID getUsuarioId() {
        return usuarioId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public UUID getFamiliaId() {
        return familiaId;
    }

    public Instant getExpiraEm() {
        return expiraEm;
    }

    public Instant getRevogadoEm() {
        return revogadoEm;
    }

    public MotivoRevogacao getMotivoRevogacao() {
        return motivoRevogacao;
    }

    public UUID getSubstituidoPorId() {
        return substituidoPorId;
    }

    public Instant getCriadoEm() {
        return criadoEm;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getIp() {
        return ip;
    }

    @Override
    public String toString() {
        return "RefreshToken{id=" + id + ", usuarioId=" + usuarioId + ", familiaId=" + familiaId
                + ", expiraEm=" + expiraEm + ", revogadoEm=" + revogadoEm + "}";
    }
}
