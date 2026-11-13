package dev.gilberto.gestaousuarios.shared.exceptions;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;

/** Refresh token inválido ou expirado (401). Não é {@code AuthenticationException} de propósito. */
public class TokenInvalidoException extends RuntimeException {

    private final String chave;

    public TokenInvalidoException(String chave) {
        super(Mensagens.get(chave));
        this.chave = chave;
    }

    public String getChave() {
        return chave;
    }
}
