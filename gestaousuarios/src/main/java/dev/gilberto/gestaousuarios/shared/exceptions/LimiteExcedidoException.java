package dev.gilberto.gestaousuarios.shared.exceptions;

import java.time.Duration;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;

/** Limite excedido (429), com o tempo a aguardar para o cabeçalho {@code Retry-After}. */
public class LimiteExcedidoException extends RuntimeException {

    private final String chave;
    private final Duration retryAfter;

    public LimiteExcedidoException(String chave, Duration retryAfter) {
        super(Mensagens.get(chave));
        this.chave = chave;
        this.retryAfter = retryAfter;
    }

    public String getChave() {
        return chave;
    }

    public Duration getRetryAfter() {
        return retryAfter;
    }
}
