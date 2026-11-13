package dev.gilberto.gestaousuarios.auth;

/** Motivo pelo qual um refresh token deixou de estar ativo. */
public enum MotivoRevogacao {
    ROTACAO,
    LOGOUT,
    LOGOUT_TODOS,
    REUSO,
    SENHA_ALTERADA,
    PERFIL_ALTERADO
}
