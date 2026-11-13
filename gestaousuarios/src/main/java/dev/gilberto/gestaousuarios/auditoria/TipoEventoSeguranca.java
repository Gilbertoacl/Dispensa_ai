package dev.gilberto.gestaousuarios.auditoria;

public enum TipoEventoSeguranca {
    LOGIN_SUCESSO,
    LOGIN_FALHA,
    LOGIN_BLOQUEADO,
    REFRESH_SUCESSO,
    REFRESH_REUSO_DETECTADO,
    LOGOUT,
    LOGOUT_TODOS,
    SENHA_ALTERADA,
    PERFIL_ALTERADO,
    ADMIN_INICIAL_CRIADO
}
