package dev.gilberto.gestaousuarios.shared.exceptions;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;

/** Violação de regra de negócio (400). A mensagem é resolvida por {@code Mensagens.get(chave)}. */
public class RegraNegocioException extends RuntimeException {

    private final String chave;
    private final String campo;

    public RegraNegocioException(String chave) {
        this(chave, null);
    }

    public RegraNegocioException(String chave, String campo) {
        super(Mensagens.get(chave));
        this.chave = chave;
        this.campo = campo;
    }

    public String getChave() {
        return chave;
    }

    /** Campo associado ao erro; pode ser nulo. */
    public String getCampo() {
        return campo;
    }
}
