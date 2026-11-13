package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Teste de integração 16.1 — boot do Flyway com Testcontainers (PostgreSQL).
 *
 * <p>Valida R13.3 (o Flyway aplica as migrações no boot) e R13.4 (a tabela {@code USUARIOS} é
 * criada com a constraint {@code UK_USUARIOS_EMAIL}). O contexto só sobe se o Flyway tiver
 * aplicado {@code V1__create_usuarios.sql} antes da validação do Hibernate
 * ({@code ddl-auto=validate}); portanto, o próprio carregamento do contexto já é um sinal de que
 * as migrações rodaram.
 *
 * <p>Além do boot, este teste confirma explicitamente — consultando o {@code information_schema} —
 * que a tabela e a constraint única existem, e faz um {@code save}+{@code findByEmail} para provar
 * que o schema validado é funcional.
 *
 * <p>Sem Docker a classe é pulada automaticamente (ver {@link AbstractPostgresIT}); com Docker a
 * execução é real.
 */
@SpringBootTest
class FlywayBootIT extends AbstractPostgresIT {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private UsuarioRepository usuarioRepository;

    // R13.3/R13.4: o Flyway criou a tabela USUARIOS no boot.
    @Test
    void flywayCriaTabelaUsuarios() {
        Integer tabelas = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.tables "
                        + "WHERE upper(table_name) = 'USUARIOS'",
                Integer.class);

        assertThat(tabelas).isEqualTo(1);
    }

    // R13.4: a constraint única UK_USUARIOS_EMAIL foi criada pela migração.
    @Test
    void flywayCriaConstraintUnicaDeEmail() {
        Integer constraints = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.table_constraints "
                        + "WHERE upper(constraint_name) = 'UK_USUARIOS_EMAIL' "
                        + "AND constraint_type = 'UNIQUE'",
                Integer.class);

        assertThat(constraints).isEqualTo(1);
    }

    // R17.2/R17.3: a V2 criou as tabelas REFRESH_TOKENS e EVENTOS_SEGURANCA.
    @ParameterizedTest
    @ValueSource(strings = {"REFRESH_TOKENS", "EVENTOS_SEGURANCA"})
    void v2CriaTabelas(String tabela) {
        Integer tabelas = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.tables WHERE upper(table_name) = ?",
                Integer.class, tabela);

        assertThat(tabelas).isEqualTo(1);
    }

    // R17.4: a V2 adicionou TOKEN_VERSION e ULTIMO_LOGIN_EM em USUARIOS.
    @ParameterizedTest
    @ValueSource(strings = {"TOKEN_VERSION", "ULTIMO_LOGIN_EM"})
    void v2AdicionaColunasEmUsuarios(String coluna) {
        Integer colunas = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.columns "
                        + "WHERE upper(table_name) = 'USUARIOS' AND upper(column_name) = ?",
                Integer.class, coluna);

        assertThat(colunas).isEqualTo(1);
    }

    // R17.5: a constraint única do hash do refresh token existe.
    @Test
    void v2CriaConstraintUnicaDoHashDoRefreshToken() {
        Integer constraints = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.table_constraints "
                        + "WHERE upper(constraint_name) = 'UK_REFRESH_TOKENS_HASH' "
                        + "AND constraint_type = 'UNIQUE'",
                Integer.class);

        assertThat(constraints).isEqualTo(1);
    }

    // R17.5: os quatro índices secundários da V2 existem (consulta a pg_indexes).
    @ParameterizedTest
    @ValueSource(strings = {
            "IDX_REFRESH_TOKENS_USUARIO", "IDX_REFRESH_TOKENS_FAMILIA",
            "IDX_EVENTOS_SEGURANCA_USUARIO", "IDX_EVENTOS_SEGURANCA_INSTANTE"})
    void v2CriaIndices(String indice) {
        Integer indices = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM pg_indexes WHERE upper(indexname) = ?",
                Integer.class, indice);

        assertThat(indices).isEqualTo(1);
    }

    // R17.6: o boot com ddl-auto=validate subiu e o Flyway aplicou a V2 com sucesso.
    @Test
    void flywayAplicouV2ComSucesso() {
        Integer aplicadas = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM flyway_schema_history "
                        + "WHERE version = '2' AND success = true",
                Integer.class);

        assertThat(aplicadas).isEqualTo(1);
    }

    // O schema validado é funcional: persiste e recupera por email normalizado.
    @Test
    void schemaValidadoPermitePersistirERecuperar() {
        Usuario salvo = usuarioRepository.save(
                new Usuario("Boot@Flyway.IT", "Boot Flyway", "hash-irrelevante", Perfil.USER));

        assertThat(salvo.getId()).isNotNull();

        Optional<Usuario> encontrado = usuarioRepository.findByEmail("boot@flyway.it");
        assertThat(encontrado).isPresent();
        assertThat(encontrado.get().getNome()).isEqualTo("Boot Flyway");
        assertThat(encontrado.get().getPerfil()).isEqualTo(Perfil.USER);
    }
}
