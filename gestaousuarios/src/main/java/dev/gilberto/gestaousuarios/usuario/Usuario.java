package dev.gilberto.gestaousuarios.usuario;

import jakarta.persistence.*;

import java.time.Instant;
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
    @Column(name = "DATA_CRIACAO", nullable = false)
    private Instant dataCriacao;

    protected Usuario() {}

    public Usuario(String email, String nome, String senhaHash) {
        this.email = normalizarEmail(email);
        this.nome = nome;
        this.senhaHash = senhaHash;
        this.dataCriacao = Instant.now();
    }

    private String normalizarEmail(String email) {
        return email.trim().toLowerCase();
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

    public Instant getDataCriacao() {
        return dataCriacao;
    }
}
