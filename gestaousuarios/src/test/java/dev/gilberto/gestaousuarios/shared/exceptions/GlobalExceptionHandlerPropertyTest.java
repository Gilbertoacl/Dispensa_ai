package dev.gilberto.gestaousuarios.shared.exceptions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Testes de propriedade (jqwik) para o {@link GlobalExceptionHandler}.
 *
 * <p>Instancia o handler diretamente e verifica que o contrato {@link ErroResponse}
 * é respeitado para falhas de validação e para as demais exceções de domínio.</p>
 */
class GlobalExceptionHandlerPropertyTest {

    private static final List<String> CAMPOS_POSSIVEIS = List.of("email", "nome", "senha");

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    // Feature: gestao-usuarios-autenticacao, Property 5: Toda violação de validação aparece em camposComErro
    @Property(tries = 100)
    void todaViolacaoAparaceEmCamposComErro(@ForAll("camposInvalidos") List<String> camposInvalidos) {
        // Monta um BindingResult com um FieldError por campo inválido gerado.
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "obj");
        for (String campo : camposInvalidos) {
            bindingResult.addError(new FieldError("obj", campo, "msg_" + campo));
        }

        // Construir MethodArgumentNotValidException via construtor exige um MethodParameter
        // não-nulo; mockamos a exceção e devolvemos o BindingResult preparado.
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        when(ex.getBindingResult()).thenReturn(bindingResult);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/v1/usuarios");

        ErroResponse corpo = handler.handleValidacao(ex, request).getBody();

        assertThat(corpo).isNotNull();
        assertThat(corpo.status()).isEqualTo(400);
        assertThat(corpo.camposComErro()).isNotNull();

        // Tamanho coerente com o número de campos distintos.
        assertThat(corpo.camposComErro()).hasSize(camposInvalidos.size());

        // Cada campo gerado aparece em camposComErro com mensagem não nula.
        for (String campo : camposInvalidos) {
            assertThat(corpo.camposComErro())
                    .anySatisfy(ce -> {
                        assertThat(ce.campo()).isEqualTo(campo);
                        assertThat(ce.mensagem()).isNotNull();
                    });
        }
    }

    @Provide
    Arbitrary<List<String>> camposInvalidos() {
        // Subconjuntos não-vazios e distintos de {email, nome, senha}, 1..3 campos.
        return Arbitraries.of(CAMPOS_POSSIVEIS)
                .list()
                .uniqueElements()
                .ofMinSize(1)
                .ofMaxSize(CAMPOS_POSSIVEIS.size());
    }

    // Feature: gestao-usuarios-autenticacao, Property 11: ErroResponse é sempre completo
    @Property(tries = 100)
    void erroResponseSempreCompleto(@ForAll("seletorDeExcecao") int seletor,
                                    @ForAll String mensagem,
                                    @ForAll("paths") String path) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(path);

        ErroResponse corpo;
        int statusEsperado;

        switch (seletor) {
            case 0 -> {
                corpo = handler.handleConflito(new ConflitoException(mensagem), request).getBody();
                statusEsperado = 409;
            }
            case 1 -> {
                corpo = handler.handleRecursoNaoEncontrado(
                        new RecursoNaoEncontradoException(mensagem), request).getBody();
                statusEsperado = 404;
            }
            case 2 -> {
                corpo = handler.handleRegraNegocio(
                        new RegraNegocioException("validation.error", "campo"), request).getBody();
                statusEsperado = 400;
            }
            default -> {
                corpo = handler.handleGenerico(new Exception(mensagem), request).getBody();
                statusEsperado = 500;
            }
        }

        assertThat(corpo).isNotNull();
        assertThat(corpo.timestamp()).isNotNull();
        assertThat(corpo.status()).isEqualTo(statusEsperado);
        assertThat(corpo.erro()).isNotNull();
        assertThat(corpo.mensagem()).isNotNull();
        assertThat(corpo.path()).isEqualTo(path);
    }

    @Provide
    Arbitrary<Integer> seletorDeExcecao() {
        return Arbitraries.integers().between(0, 3);
    }

    @Provide
    Arbitrary<String> paths() {
        Arbitrary<String> segmento = Arbitraries.strings()
                .withCharRange('a', 'z')
                .ofMinLength(1)
                .ofMaxLength(10);
        return segmento.map(s -> "/v1/" + s);
    }
}
