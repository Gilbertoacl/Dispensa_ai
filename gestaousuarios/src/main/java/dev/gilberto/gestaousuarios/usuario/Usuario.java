package dev.gilberto.gestaousuarios.usuario;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

@Entity
@Table(name = "USUARIOS", uniqueConstraints = @UniqueConstraint(name = "UK_USUARIOS_EMAIL", columnNames = "EMAIL"))
public class Usuario {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false, length = 254)
    private String email;
    @Column(nullable = false, length = 100)
    private String nome;
    @Column(name = "SENHA_HASH", nullable = false, length = 255)
    private String senhaHash;
    @Enumerated(EnumType.STRING)
    @Column(name = "PERFIL", nullable = false, length = 20)
    private Perfil perfil;
    @Column(name = "DATA_CRIACAO", nullable = false)
    private Instant dataCriacao;
    // updatable = false: incrementos ocorrem por UPDATE atomico no repositorio; o Hibernate nao deve regravar a versao antiga
    @Column(name = "TOKEN_VERSION", nullable = false, updatable = false)
    private int tokenVersion;
    @Column(name = "ULTIMO_LOGIN_EM", updatable = false)
    private Instant ultimoLoginEm;

    protected Usuario() {}

    public Usuario(String email, String nome, String senhaHash) {
        this(email, nome, senhaHash, Perfil.USER);
    }

    public Usuario(String email, String nome, String senhaHash, Perfil perfil) {
        this.email = normalizarEmail(email);
        this.nome = nome;
        this.senhaHash = senhaHash;
        this.perfil = perfil != null ? perfil : Perfil.USER;
        this.dataCriacao = Instant.now();
    }

    public static String normalizarEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getNome() {
        return nome;
    }

    public String getSenhaHash() {
        return senhaHash;
    }

    public Perfil getPerfil() {
        return perfil;
    }

    public Instant getDataCriacao() {
        return dataCriacao;
    }

    public int getTokenVersion() {
        return tokenVersion;
    }

    public Instant getUltimoLoginEm() {
        return ultimoLoginEm;
    }

    public void alterarPerfil(Perfil perfil) {
        this.perfil = perfil;
    }

    public void alterarNome(String nome) {
        this.nome = nome;
    }

    public void alterarSenhaHash(String senhaHash) {
        this.senhaHash = senhaHash;
    }
}
