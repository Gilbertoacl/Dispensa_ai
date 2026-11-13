package dev.gilberto.gestaousuarios.usuario;

import java.util.UUID;

import dev.gilberto.gestaousuarios.auth.MotivoRevogacao;

/**
 * Porta pela qual o pacote {@code usuario} revoga ou remove sessões (refresh tokens) sem depender
 * da implementação em {@code auth}. As operações exigem transação já aberta pelo chamador.
 */
public interface RevogadorDeSessoes {

    /** Revoga todos os refresh tokens ativos do usuário com o motivo informado. */
    void revogarTodas(UUID usuarioId, MotivoRevogacao motivo);

    /** Remove todos os refresh tokens do usuário (exclusão de conta). */
    void removerTodas(UUID usuarioId);

    /** Implementação sem efeito, para testes unitários. */
    static RevogadorDeSessoes semEfeito() {
        return new RevogadorDeSessoes() {
            @Override
            public void revogarTodas(UUID usuarioId, MotivoRevogacao motivo) { }

            @Override
            public void removerTodas(UUID usuarioId) { }
        };
    }
}
