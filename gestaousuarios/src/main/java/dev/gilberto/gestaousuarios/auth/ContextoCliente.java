package dev.gilberto.gestaousuarios.auth;

/**
 * Dados do cliente da requisição, usados em sessões e auditoria.
 */
public record ContextoCliente(String ip, String userAgent) {}
