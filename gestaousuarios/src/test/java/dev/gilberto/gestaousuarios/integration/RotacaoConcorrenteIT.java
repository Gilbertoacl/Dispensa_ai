package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IT 16.4: N threads apresentam o MESMO refresh token ativo ao mesmo tempo (servidor real,
 * RANDOM_PORT, transações reais no PostgreSQL).
 *
 * <p>Resultado esperado pelo design (rotação atômica por UPDATE condicional + detecção de reuso):
 * exatamente uma rotação vence (200); as perdedoras releem o token já consumido
 * ({@code SUBSTITUIDO_POR_ID} preenchido) e tratam como REUSO: 401 {@code refresh.reutilizado}
 * e a família inteira é revogada (inclusive o token emitido ao vencedor). Logo, no fim, a família
 * tem no máximo 1 token ativo (na prática 0, pois há perdedoras).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RotacaoConcorrenteIT extends AbstractPostgresIT {

    private static final int THREADS = 8;

    @LocalServerPort
    private int porta;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JdbcTemplate jdbc;

    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> post(String caminho, Object corpo) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://localhost:" + porta + caminho))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(corpo)))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    @RepeatedTest(5)
    void refreshConcorrenteComOMesmoTokenTemUmUnicoVencedor() throws Exception {
        String email = "conc." + UUID.randomUUID() + "@dispensa.ai";
        String senha = "Fluxo#" + UUID.randomUUID().toString().substring(0, 18);
        HttpResponse<String> cadastro = post("/v1/usuarios",
                Map.of("email", email, "nome", "Concorrente", "senha", senha));
        assertThat(cadastro.statusCode()).isEqualTo(201);
        UUID usuarioId = UUID.fromString(objectMapper.readTree(cadastro.body()).get("id").asString());

        HttpResponse<String> login = post("/v1/auth/login", Map.of("email", email, "senha", senha));
        assertThat(login.statusCode()).isEqualTo(200);
        String refresh = objectMapper.readTree(login.body()).get("refreshToken").asString();

        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch prontas = new CountDownLatch(THREADS);
        CountDownLatch largada = new CountDownLatch(1);
        List<Future<HttpResponse<String>>> futuros = new ArrayList<>();
        try {
            for (int i = 0; i < THREADS; i++) {
                futuros.add(pool.submit(() -> {
                    prontas.countDown();
                    largada.await();
                    return post("/v1/auth/refresh", Map.of("refreshToken", refresh));
                }));
            }
            assertThat(prontas.await(30, TimeUnit.SECONDS)).isTrue();
            largada.countDown();

            int ok = 0;
            int naoAutorizado = 0;
            for (Future<HttpResponse<String>> futuro : futuros) {
                HttpResponse<String> r = futuro.get(60, TimeUnit.SECONDS);
                if (r.statusCode() == 200) {
                    ok++;
                } else {
                    assertThat(r.statusCode()).as("perdedora: %s", r.body()).isEqualTo(401);
                    JsonNode corpo = objectMapper.readTree(r.body());
                    assertThat(corpo.get("mensagem").asString()).isEqualTo(Mensagens.get("refresh.reutilizado"));
                    naoAutorizado++;
                }
            }
            assertThat(ok).as("exatamente uma rotação vence").isEqualTo(1);
            assertThat(naoAutorizado).isEqualTo(THREADS - 1);
        } finally {
            pool.shutdownNow();
        }

        // Estado no banco: uma única rotação (2 linhas na família), no máximo 1 ativo (aqui, 0:
        // o reuso detectado pelas perdedoras revogou a família inteira).
        List<Map<String, Object>> linhas = jdbc.queryForList(
                "select familia_id, revogado_em, substituido_por_id from refresh_tokens where usuario_id = ?",
                usuarioId);
        assertThat(linhas).hasSize(2);
        assertThat(linhas).extracting(l -> l.get("familia_id")).containsOnly(linhas.get(0).get("familia_id"));
        assertThat(linhas.stream().filter(l -> l.get("revogado_em") == null).count())
                .as("tokens ativos na família").isLessThanOrEqualTo(1L).isZero();
        assertThat(linhas.stream().filter(l -> l.get("substituido_por_id") != null).count()).isEqualTo(1L);
        assertThat(jdbc.queryForObject(
                "select count(*) from eventos_seguranca where usuario_id = ? and tipo = 'REFRESH_SUCESSO'",
                Integer.class, usuarioId)).isEqualTo(1);
    }
}
