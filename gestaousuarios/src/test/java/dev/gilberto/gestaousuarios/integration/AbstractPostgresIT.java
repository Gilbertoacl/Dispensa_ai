package dev.gilberto.gestaousuarios.integration;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Base reutilizável para os testes de integração fim-a-fim (IT) que exercem o serviço contra um
 * PostgreSQL real provisionado via Testcontainers.
 *
 * <p><strong>Pular sem Docker.</strong> A anotação {@link Testcontainers} com
 * {@code disabledWithoutDocker = true} faz com que a classe inteira (e, por herança, as subclasses)
 * seja automaticamente <em>pulada</em> (não falha) quando o Docker não está disponível no ambiente.
 * Assim, {@code test-compile} sempre compila e, sem Docker, os ITs são reportados como
 * <em>skipped</em>; com Docker ligado futuramente, eles executam de verdade, sem baixar imagem
 * quando pulados.
 *
 * <p><strong>Perfil e configuração.</strong> Os ITs NÃO usam o profile {@code test} (que desliga o
 * Flyway e usa H2). Em vez disso, mantemos o default do {@code application.yml} base
 * ({@code PROFILE:prod}, {@code flyway.enabled=true}, {@code ddl-auto=validate}) e sobrepomos o
 * datasource com as coordenadas do container PostgreSQL via {@link DynamicPropertySource}. O Flyway
 * aplica {@code V1__create_usuarios.sql} no boot e o Hibernate apenas valida o schema resultante.
 *
 * <p>Também fornecemos um segredo JWT com pelo menos 32 bytes (exigência do HS256) e mantemos os
 * eventos Kafka desabilitados (já é o default).
 */
@ExtendWith(AbstractPostgresIT.CondicaoBanco.class)
public abstract class AbstractPostgresIT {

    /** Credenciais do Admin_Inicial usadas pelos ITs (somente teste). */
    protected static final String ADMIN_EMAIL = "admin.it@dispensa.ai";
    protected static final String ADMIN_SENHA = "AdminIt#Segura2026";
    protected static final String ADMIN_NOME = "Admin IT";

    /**
     * Modo (a): PostgreSQL externo, quando {@code IT_DB_URL} (propriedade de sistema ou variável de
     * ambiente) está definida, junto com {@code IT_DB_USER} e {@code IT_DB_PASSWORD}. Nenhum
     * container é iniciado. O banco deve estar limpo antes da suíte
     * (recrie o banco dedicado antes da execução).
     * Modo (b): Testcontainers (singleton lazy), exige Docker; sem Docker os ITs são pulados.
     */
    private static PostgreSQLContainer<?> container;

    private static String config(String nome) {
        String v = System.getProperty(nome);
        if (v == null || v.isBlank()) {
            v = System.getenv(nome);
        }
        return (v == null || v.isBlank()) ? null : v;
    }

    private static boolean modoExterno() {
        return config("IT_DB_URL") != null;
    }

    private static synchronized PostgreSQLContainer<?> container() {
        if (container == null) {
            @SuppressWarnings("resource")
            PostgreSQLContainer<?> c = new PostgreSQLContainer<>("postgres:16-alpine");
            c.start();
            Runtime.getRuntime().addShutdownHook(new Thread(c::stop));
            container = c;
        }
        return container;
    }

    private static String url() {
        return modoExterno() ? config("IT_DB_URL") : container().getJdbcUrl();
    }

    private static String usuario() {
        return modoExterno() ? config("IT_DB_USER") : container().getUsername();
    }

    private static String senha() {
        return modoExterno() ? config("IT_DB_PASSWORD") : container().getPassword();
    }

    /** Habilita a classe se houver banco externo configurado OU Docker disponível. */
    static class CondicaoBanco implements ExecutionCondition {
        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
            if (modoExterno()) {
                return ConditionEvaluationResult.enabled("IT_DB_URL definida: banco externo");
            }
            boolean docker;
            try {
                docker = DockerClientFactory.instance().isDockerAvailable();
            } catch (Throwable t) {
                docker = false;
            }
            return docker
                    ? ConditionEvaluationResult.enabled("Docker disponível: Testcontainers")
                    : ConditionEvaluationResult.disabled(
                            "Sem IT_DB_URL e sem Docker: ITs pulados");
        }
    }

    /**
     * Sobrepõe as propriedades do contexto Spring para apontar o datasource ao container e garantir
     * que o Flyway aplique as migrações antes da validação do Hibernate.
     *
     * <p>As chaves {@code spring.datasource.*} têm precedência sobre os placeholders
     * {@code ${DATASOURCE_*}} do {@code application.yml} base, de modo que nenhuma variável de
     * ambiente precisa estar presente.
     */
    @DynamicPropertySource
    static void registrarPropriedades(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", AbstractPostgresIT::url);
        registry.add("spring.datasource.username", AbstractPostgresIT::usuario);
        registry.add("spring.datasource.password", AbstractPostgresIT::senha);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");

        // Flyway habilitado + ddl-auto validate: o schema é criado pelas migrações e validado
        // pelo Hibernate. (Ambos já são o default do application.yml, reforçados aqui.)
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.jpa.properties.hibernate.dialect",
                () -> "org.hibernate.dialect.PostgreSQLDialect");

        // Segredo HMAC com >= 32 bytes para HS256 (emissão/validação do JWT).
        registry.add("dispensaai.security.jwt.secret",
                () -> "it-only-secret-0123456789-0123456789-abcdef");
        registry.add("dispensaai.security.jwt.access-expiration", () -> "900");

        registry.add("dispensaai.security.refresh.expiration", () -> "7d");

        // Rate limit alto (máximo permitido) para não interferir nos fluxos; lockout mantém o
        // padrão (5 tentativas/15m) e é por conta, então os testes usam e-mails únicos.
        registry.add("dispensaai.security.ratelimit.max-requests", () -> "10000");
        registry.add("dispensaai.security.ratelimit.window", () -> "1m");
        registry.add("dispensaai.security.lockout.max-attempts", () -> "5");

        // Admin inicial (criado no boot pelo runner); credenciais só existem em código de teste.
        // A senha respeita a PasswordPolicy (8-64, != e-mail, fora da lista de comuns).
        registry.add("dispensaai.admin-inicial.email", () -> ADMIN_EMAIL);
        registry.add("dispensaai.admin-inicial.senha", () -> ADMIN_SENHA);
        registry.add("dispensaai.admin-inicial.nome", () -> ADMIN_NOME);

        // Eventos de domínio desabilitados (default), para subir sem broker Kafka.
        registry.add("dispensaai.eventos.usuario-criado.enabled", () -> "false");
    }
}
