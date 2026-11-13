package dev.gilberto.gestaousuarios.usuario;

import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;

/**
 * Cria o administrador inicial no boot, de forma idempotente, quando ADMIN_EMAIL, ADMIN_SENHA e
 * ADMIN_NOME estão todas definidas. Nunca registra a senha.
 */
@Component
public class AdminInicialInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminInicialInitializer.class);

    private final AdminInicialProperties properties;
    private final UsuarioService usuarioService;

    public AdminInicialInitializer(AdminInicialProperties properties, UsuarioService usuarioService) {
        this.properties = properties;
        this.usuarioService = usuarioService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.completo()) {
            log.info("Admin inicial não configurado (ADMIN_EMAIL, ADMIN_SENHA e ADMIN_NOME); nada a criar.");
            return;
        }
        Optional<UUID> criado;
        try {
            criado = usuarioService.criarAdminInicial(
                    properties.email().trim(), properties.nome().trim(), properties.senha());
        } catch (RegraNegocioException e) {
            throw new IllegalStateException(Mensagens.get("admin.inicial.senha.invalida", e.getChave()));
        }
        if (criado.isPresent()) {
            log.info("Admin inicial criado com id {}", criado.get());
        } else {
            log.info("Admin inicial já existe; nenhuma alteração.");
        }
    }
}
