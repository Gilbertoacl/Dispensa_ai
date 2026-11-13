package dev.gilberto.gestaousuarios.auditoria;

import java.util.UUID;

/**
 * Porta de auditoria de segurança. Implementações não devem propagar falhas ao fluxo principal.
 */
public interface AuditoriaSeguranca {

    void registrar(TipoEventoSeguranca tipo, UUID usuarioId, String detalhe);

    /** Implementação sem efeito, para testes unitários e troca defensiva nos construtores. */
    static AuditoriaSeguranca semEfeito() {
        return (tipo, usuarioId, detalhe) -> { };
    }
}
