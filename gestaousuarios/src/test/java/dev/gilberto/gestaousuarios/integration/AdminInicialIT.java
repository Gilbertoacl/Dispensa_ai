package dev.gilberto.gestaousuarios.integration;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.gilberto.gestaousuarios.GestaousuariosApplication;
import dev.gilberto.gestaousuarios.integration.AuthFlowHelper.Tokens;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT 16.7: Admin_Inicial. O contexto do teste é o primeiro boot (cria o admin configurado em
 * {@link AbstractPostgresIT}, ou já o encontra de outros ITs); um segundo boot, contra o mesmo
 * banco, deve ser idempotente; senha inválida impede o boot; a senha nunca aparece nos logs.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AdminInicialIT extends AbstractPostgresIT {

    private static final String[] CHAVES_DO_AMBIENTE = {
            "spring.datasource.url", "spring.datasource.username", "spring.datasource.password",
            "spring.datasource.driver-class-name", "spring.flyway.enabled", "spring.jpa.hibernate.ddl-auto",
            "spring.jpa.properties.hibernate.dialect", "dispensaai.security.jwt.secret",
            "dispensaai.security.jwt.access-expiration", "dispensaai.security.refresh.expiration",
            "dispensaai.security.ratelimit.max-requests", "dispensaai.security.ratelimit.window",
            "dispensaai.security.lockout.max-attempts", "dispensaai.eventos.usuario-criado.enabled"
    };

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private Environment env;

    private ListAppender<ILoggingEvent> appender;
    private Logger root;
    private Level nivelOriginal;

    @BeforeEach
    void capturarLogs() {
        root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        nivelOriginal = root.getLevel();
        root.setLevel(Level.ALL);
        appender = new ListAppender<>();
        appender.start();
        root.addAppender(appender);
    }

    @AfterEach
    void liberarLogs() {
        root.detachAppender(appender);
        root.setLevel(nivelOriginal);
    }

    private String logs() {
        StringBuilder sb = new StringBuilder();
        for (ILoggingEvent e : new ArrayList<>(appender.list)) {
            sb.append(e.getFormattedMessage()).append('\n');
            if (e.getThrowableProxy() != null) {
                sb.append(e.getThrowableProxy().getMessage()).append('\n');
            }
        }
        return sb.toString();
    }

    /** Propriedades de um segundo boot: mesmo banco/segredos, sem servidor web. */
    private List<String> propriedades(String email, String senha, String nome) {
        List<String> props = new ArrayList<>();
        for (String chave : CHAVES_DO_AMBIENTE) {
            String valor = env.getProperty(chave);
            if (valor != null) {
                props.add(chave + "=" + valor);
            }
        }
        props.add("dispensaai.admin-inicial.email=" + email);
        props.add("dispensaai.admin-inicial.senha=" + senha);
        props.add("dispensaai.admin-inicial.nome=" + nome);
        props.add("spring.main.banner-mode=off");
        return props;
    }

    /** Propriedades passadas como argumentos de linha de comando (maior precedência que o yml). */
    private ConfigurableApplicationContext subir(String email, String senha, String nome) {
        // O LoggingSystem real do Boot reinicializa (reset) o Logback a cada novo boot após o
        // fechamento de um contexto, o que removeria o appender de captura deste teste.
        String chaveLogging = "org.springframework.boot.logging.LoggingSystem";
        String anterior = System.getProperty(chaveLogging);
        System.setProperty(chaveLogging, "none");
        try {
            return new SpringApplicationBuilder(GestaousuariosApplication.class)
                    .web(WebApplicationType.NONE)
                    .run(propriedades(email, senha, nome).stream().map(p -> "--" + p).toArray(String[]::new));
        } finally {
            if (anterior == null) {
                System.clearProperty(chaveLogging);
            } else {
                System.setProperty(chaveLogging, anterior);
            }
        }
    }

    private List<Map<String, Object>> admins(String email) {
        return jdbc.queryForList(
                "select id, email, nome, senha_hash, perfil, token_version, data_criacao "
                        + "from usuarios where email = ?", email);
    }

    @Test
    void adminConfiguradoExisteComPerfilAdminELogaEAcessaUsuarios() throws Exception {
        List<Map<String, Object>> linhas = admins(ADMIN_EMAIL);
        assertThat(linhas).hasSize(1);
        assertThat(linhas.get(0).get("perfil")).isEqualTo("ADMIN");
        assertThat(linhas.get(0).get("nome")).isEqualTo(ADMIN_NOME);
        assertThat((String) linhas.get(0).get("senha_hash")).startsWith("$2").doesNotContain(ADMIN_SENHA);

        AuthFlowHelper f = new AuthFlowHelper(mockMvc, objectMapper);
        Tokens admin = f.login(ADMIN_EMAIL, ADMIN_SENHA);
        mockMvc.perform(get("/v1/usuarios").header("Authorization", AuthFlowHelper.bearer(admin)))
                .andExpect(status().isOk());
    }

    @Test
    void segundoBootNaoDuplicaNemAlteraOAdmin() {
        Map<String, Object> antes = admins(ADMIN_EMAIL).get(0);

        try (ConfigurableApplicationContext segundo = subir(ADMIN_EMAIL, ADMIN_SENHA, ADMIN_NOME)) {
            assertThat(segundo.isRunning()).isTrue();
        }
        // Mesmo e-mail com outra senha/nome na configuração: continua sem alterar o existente.
        String outraSenha = "Outra#Senha" + UUID.randomUUID().toString().substring(0, 12);
        try (ConfigurableApplicationContext terceiro = subir(ADMIN_EMAIL, outraSenha, "Outro Nome")) {
            assertThat(terceiro.isRunning()).isTrue();
        }

        List<Map<String, Object>> depois = admins(ADMIN_EMAIL);
        assertThat(depois).hasSize(1);
        assertThat(depois.get(0)).isEqualTo(antes);
        assertThat(logs()).contains("existe; nenhuma").doesNotContain(ADMIN_SENHA).doesNotContain(outraSenha);
    }

    @Test
    void novoAdminEhCriadoUmaVezEIdempotenteNoReboot() {
        String email = "admin." + UUID.randomUUID() + "@dispensa.ai";
        String senha = "Boot#" + UUID.randomUUID().toString().substring(0, 18);

        try (ConfigurableApplicationContext c = subir(email, senha, "Admin Novo")) {
            assertThat(c.isRunning()).isTrue();
        }
        Map<String, Object> criado = admins(email).get(0);
        assertThat(criado.get("perfil")).isEqualTo("ADMIN");
        assertThat(jdbc.queryForObject(
                "select count(*) from eventos_seguranca where usuario_id = ? and tipo = 'ADMIN_INICIAL_CRIADO'",
                Integer.class, criado.get("id"))).isEqualTo(1);

        try (ConfigurableApplicationContext c = subir(email, senha, "Admin Novo")) {
            assertThat(c.isRunning()).isTrue();
        }
        assertThat(admins(email)).hasSize(1).first().isEqualTo(criado);
        assertThat(jdbc.queryForObject(
                "select count(*) from eventos_seguranca where usuario_id = ? and tipo = 'ADMIN_INICIAL_CRIADO'",
                Integer.class, criado.get("id"))).isEqualTo(1);
        assertThat(logs()).contains("Admin inicial criado").doesNotContain(senha);
    }

    @Test
    void senhaInvalidaNaConfiguracaoImpedeOBootSemVazarASenha() {
        String email = "admin.invalido." + UUID.randomUUID() + "@dispensa.ai";
        String senhaFraca = "password123";

        assertThatThrownBy(() -> subir(email, senhaFraca, "Admin Invalido"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ADMIN_SENHA")
                .satisfies(e -> assertThat(rootMessage(e)).doesNotContain(senhaFraca));

        assertThat(admins(email)).isEmpty();
        assertThat(logs()).doesNotContain(senhaFraca);
    }

    private static String rootMessage(Throwable t) {
        Throwable r = t;
        while (r.getCause() != null) {
            r = r.getCause();
        }
        return String.valueOf(r.getMessage());
    }
}
