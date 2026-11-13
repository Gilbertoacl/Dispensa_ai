package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import tools.jackson.databind.json.JsonMapper;

class CadastroPublicoPropertyTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    // Feature: endurecimento-autenticacao, Property 9: Cadastro público sempre cria USER com tokenVersion 0
    // Validates: Requirements 6.1, 6.2, 6.4, 6.5
    @Property(tries = 200)
    void cadastroPublicoSempreCriaUserComTokenVersionZero(@ForAll("localPart") String local,
                                                          @ForAll("nomes") String nome,
                                                          @ForAll("perfisNoCorpo") String fragmentoPerfil) {
        String email = local + "@example.com";
        String senha = "Zq#" + local + "9Xw";
        String json = "{\"email\":\"" + email + "\",\"nome\":\"" + nome + "\",\"senha\":\"" + senha + "\""
                + fragmentoPerfil + "}";

        UsuarioRequest req = MAPPER.readValue(json, UsuarioRequest.class);
        assertThat(req.email()).isEqualTo(email);

        UsuarioRepository repo = mock(UsuarioRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        when(repo.existsByEmail(any())).thenReturn(false);
        when(encoder.encode(any())).thenReturn("HASH");
        when(repo.save(any(Usuario.class))).thenAnswer(inv -> inv.getArgument(0));

        UsuarioResponse response = new UsuarioService(repo, encoder).criarUsuario(req);

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(repo).save(captor.capture());
        assertThat(captor.getValue().getPerfil()).isEqualTo(Perfil.USER);
        assertThat(captor.getValue().getTokenVersion()).isZero();
        assertThat(response.perfil()).isEqualTo(Perfil.USER);
    }

    @Provide
    Arbitrary<String> localPart() {
        return Arbitraries.strings().withCharRange('a', 'z').withCharRange('0', '9').ofMinLength(3).ofMaxLength(12);
    }

    @Provide
    Arbitrary<String> nomes() {
        return Arbitraries.strings().withCharRange('a', 'z').withCharRange('A', 'Z').ofMinLength(1).ofMaxLength(30);
    }

    /** Trecho JSON do campo perfil: ausente, ADMIN, USER, null ou string aleatória. */
    @Provide
    Arbitrary<String> perfisNoCorpo() {
        Arbitrary<String> aleatorio = Arbitraries.strings().alpha().numeric().ofMaxLength(15)
                .map(s -> ",\"perfil\":\"" + s + "\"");
        return Arbitraries.oneOf(
                Arbitraries.just(""),
                Arbitraries.just(",\"perfil\":\"ADMIN\""),
                Arbitraries.just(",\"perfil\":\"USER\""),
                Arbitraries.just(",\"perfil\":null"),
                aleatorio);
    }
}
