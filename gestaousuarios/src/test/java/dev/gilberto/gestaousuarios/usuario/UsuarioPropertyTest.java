package dev.gilberto.gestaousuarios.usuario;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Testes de propriedade (jqwik) para a entidade {@link Usuario}.
 */
class UsuarioPropertyTest {

    // Feature: gestao-usuarios-autenticacao, Property 1: Normalização de email é determinística e idempotente
    @Property(tries = 100)
    void normalizacaoDeEmailDeterministicaEIdempotente(@ForAll("emailsComRuido") String emailBruto) {
        String esperado = emailBruto.trim().toLowerCase();

        // Determinismo: a normalização produz sempre o mesmo resultado para a mesma entrada
        String primeiraNormalizacao = new Usuario(emailBruto, "n", "h", Perfil.USER).getEmail();
        String segundaNormalizacao = new Usuario(emailBruto, "n", "h", Perfil.USER).getEmail();

        assertThat(primeiraNormalizacao).isEqualTo(esperado);
        assertThat(segundaNormalizacao).isEqualTo(esperado);
        assertThat(primeiraNormalizacao).isEqualTo(segundaNormalizacao);

        // Idempotência: normalizar um email já normalizado não muda o resultado
        String renormalizado = new Usuario(primeiraNormalizacao, "n", "h", Perfil.USER).getEmail();
        assertThat(renormalizado).isEqualTo(primeiraNormalizacao);
    }

    @Provide
    Arbitrary<String> emailsComRuido() {
        Arbitrary<String> local = Arbitraries.strings()
                .withCharRange('a', 'z')
                .withCharRange('A', 'Z')
                .withCharRange('0', '9')
                .ofMinLength(1)
                .ofMaxLength(12);
        Arbitrary<String> dominio = Arbitraries.of(
                "Example.COM", "GMAIL.com", "Empresa.Com.BR", "Test.Org", "DOMAIN.io");
        Arbitrary<String> espacoEsquerda = Arbitraries.of("", " ", "  ", "\t", " \t ");
        Arbitrary<String> espacoDireita = Arbitraries.of("", " ", "  ", "\t", " \t ");

        return Combinators.combine(espacoEsquerda, local, dominio, espacoDireita)
                .as((esq, user, dom, dir) -> esq + user + "@" + dom + dir);
    }

    // Feature: gestao-usuarios-autenticacao, Property 7: Perfil é sempre um valor válido do enum
    @Property(tries = 100)
    void perfilSempreValido(@ForAll Perfil perfil) {
        Usuario usuario = new Usuario("user@example.com", "Nome", "hash", perfil);

        assertThat(usuario.getPerfil())
                .isNotNull()
                .isIn((Object[]) Perfil.values());

        // Perfil nulo no construtor de 4 argumentos assume USER por padrão
        Usuario comPerfilNulo = new Usuario("user@example.com", "Nome", "hash", null);
        assertThat(comPerfilNulo.getPerfil()).isEqualTo(Perfil.USER);
    }
}
