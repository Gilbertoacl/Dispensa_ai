package dev.gilberto.gestaousuarios.shared.exceptions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/** Propriedade 21: ErroResponse completo e coerente para toda exceção tratada. */
class ErroResponseCompletoPropertyTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    // Feature: endurecimento-autenticacao, Property 21: ErroResponse completo e coerente para toda exceção tratada
    // Validates: Requirements 15.2, 15.4, 15.5, 15.6
    @Property(tries = 200)
    void erroResponseCompletoECoerente(@ForAll("seletor") int seletor,
                                       @ForAll("textos") String mensagem,
                                       @ForAll("paths") String path,
                                       @ForAll("duracoes") Duration retryAfter) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRequestURI(path);

        ResponseEntity<ErroResponse> resp;
        int esperado;
        switch (seletor) {
            case 0 -> { resp = handler.handleRegraNegocio(new RegraNegocioException("perfil.invalido"), req); esperado = 400; }
            case 1 -> { resp = handler.handleRegraNegocio(new RegraNegocioException("senha.comum", "novaSenha"), req); esperado = 400; }
            case 2 -> { resp = handler.handleTokenInvalido(new TokenInvalidoException("refresh.invalido"), req); esperado = 401; }
            case 3 -> { resp = handler.handleTokenInvalido(new TokenReutilizadoException(), req); esperado = 401; }
            case 4 -> { resp = handler.handleLimiteExcedido(new LimiteExcedidoException("login.bloqueado", retryAfter), req); esperado = 429; }
            case 5 -> { resp = handler.handleTipoInvalido(new MethodArgumentTypeMismatchException(
                    mensagem, java.util.UUID.class, "id", null, new IllegalArgumentException(mensagem)), req); esperado = 400; }
            case 6 -> { resp = handler.handleCorpoIlegivel(
                    new HttpMessageNotReadableException(mensagem, mock(HttpInputMessage.class)), req); esperado = 400; }
            case 7 -> { resp = handler.handleArgumentoInvalido(new IllegalArgumentException(mensagem), req); esperado = 500; }
            case 8 -> { resp = handler.handleGenerico(new Exception(mensagem), req); esperado = 500; }
            case 9 -> { resp = handler.handleConflito(new ConflitoException(mensagem), req); esperado = 409; }
            default -> { resp = handler.handleRecursoNaoEncontrado(new RecursoNaoEncontradoException(mensagem), req); esperado = 404; }
        }

        ErroResponse corpo = resp.getBody();
        assertThat(corpo).isNotNull();
        assertThat(corpo.timestamp()).isNotNull();
        assertThat(corpo.erro()).isNotNull();
        assertThat(corpo.mensagem()).isNotNull();
        assertThat(corpo.path()).isEqualTo(path);
        assertThat(corpo.status()).isEqualTo(esperado);
        assertThat(resp.getStatusCode().value()).isEqualTo(esperado);

        String retry = resp.getHeaders().getFirst(HttpHeaders.RETRY_AFTER);
        if (esperado == 429) {
            assertThat(retry).isNotNull();
            assertThat(Long.parseLong(retry)).isGreaterThanOrEqualTo(1);
            assertThat(Long.parseLong(retry)).isGreaterThanOrEqualTo(retryAfter.getSeconds());
        } else {
            assertThat(retry).isNull();
        }

        if (esperado == 500) {
            assertThat(corpo.mensagem()).isEqualTo("Erro interno no servidor");
            if (!mensagem.isBlank() && !"Erro interno no servidor".contains(mensagem)) {
                assertThat(corpo.mensagem()).doesNotContain(mensagem);
            }
        }
        if (seletor == 5) {
            assertThat(corpo.camposComErro()).singleElement()
                    .satisfies(c -> assertThat(c.campo()).isEqualTo("id"));
        }
        if (seletor == 1) {
            assertThat(corpo.camposComErro()).singleElement()
                    .satisfies(c -> assertThat(c.campo()).isEqualTo("novaSenha"));
        }
    }

    @Provide
    Arbitrary<Integer> seletor() {
        return Arbitraries.integers().between(0, 10);
    }

    @Provide
    Arbitrary<String> textos() {
        return Arbitraries.strings().ofMinLength(1).ofMaxLength(60);
    }

    @Provide
    Arbitrary<Duration> duracoes() {
        return Arbitraries.longs().between(0, 3_600_000L).map(Duration::ofMillis);
    }

    @Provide
    Arbitrary<String> paths() {
        return Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1).ofMaxLength(10).map(s -> "/v1/" + s);
    }
}
