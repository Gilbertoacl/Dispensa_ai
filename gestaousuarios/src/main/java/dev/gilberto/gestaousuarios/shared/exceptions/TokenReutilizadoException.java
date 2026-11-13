package dev.gilberto.gestaousuarios.shared.exceptions;

/** Reuso de refresh token já rotacionado (401, chave {@code refresh.reutilizado}). */
public class TokenReutilizadoException extends TokenInvalidoException {

    public TokenReutilizadoException() {
        super("refresh.reutilizado");
    }
}
