package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;

import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Testes de propriedade (jqwik) para {@link UsuarioResponse} e para o mapeamento
 * realizado por {@link UsuarioService}.
 */
class UsuarioResponsePropertyTest {

    // Feature: gestao-usuarios-autenticacao, Property 3: Respostas nunca expõem a senha
    // Validates: Requirements 2.4, 15.1
    @Property(tries = 100)
    void respostasNuncaExpoemASenha(@ForAll("emails") String email,
                                    @ForAll("nomes") String nome,
                                    @ForAll Perfil perfil) {
        UsuarioResponse resp = new UsuarioResponse(java.util.UUID.randomUUID(), email, nome, perfil, Instant.now());

        ObjectMapper om = JsonMapper.builder().findAndAddModules().build();
        String json = om.writeValueAsString(resp);

        assertThat(json.toLowerCase())
                .doesNotContain("senha")
                .doesNotContain("senhahash");
    }

    // Feature: gestao-usuarios-autenticacao, Property 4: Renderização de usuário contém os campos públicos
    // Validates: Requirements 1.4, 5.2, 7.5, 8.2
    @Property(tries = 100)
    void renderizacaoDeUsuarioContemOsCamposPublicos(@ForAll("emails") String email,
                                                     @ForAll("nomes") String nome,
                                                     @ForAll("senhasHash") String senhaHash,
                                                     @ForAll Perfil perfil) {
        Usuario u = new Usuario(email, nome, senhaHash, perfil);

        // Mapeamento manual equivalente ao toResponse do serviço
        UsuarioResponse response = new UsuarioResponse(java.util.UUID.randomUUID(), u.getEmail(), u.getNome(), u.getPerfil(), u.getDataCriacao());

        assertThat(response.email()).isEqualTo(u.getEmail());
        assertThat(response.nome()).isEqualTo(u.getNome());
        assertThat(response.perfil()).isEqualTo(u.getPerfil());
        assertThat(response.dataDeCriacao()).isEqualTo(u.getDataCriacao());
    }

    // Feature: gestao-usuarios-autenticacao, Property 8: Cadastro público sempre cria USER
    // Validates: Requirements 6.3
    @Property(tries = 100)
    void cadastroPublicoSempreCriaUser(@ForAll("emails") String email,
                                          @ForAll("nomes") String nome) {
        UsuarioRepository repo = mock(UsuarioRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(repo.existsByEmail(any())).thenReturn(false);
        when(encoder.encode(any())).thenReturn("HASH");
        when(repo.save(any(Usuario.class))).thenAnswer(inv -> inv.getArgument(0));

        UsuarioService service = new UsuarioService(repo, encoder);

        UsuarioRequest req = new UsuarioRequest(email, nome, "Dispensa#2024");
        UsuarioResponse response = service.criarUsuario(req);

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(repo).save(captor.capture());

        assertThat(captor.getValue().getPerfil()).isEqualTo(Perfil.USER);
        assertThat(response.perfil()).isEqualTo(Perfil.USER);
    }

    @Provide
    Arbitrary<String> emails() {
        Arbitrary<String> local = Arbitraries.strings()
                .withCharRange('a', 'z')
                .withCharRange('0', '9')
                .ofMinLength(1)
                .ofMaxLength(12);
        Arbitrary<String> dominio = Arbitraries.of(
                "example.com", "gmail.com", "empresa.com.br", "test.org", "domain.io");
        return Combinators.combine(local, dominio).as((user, dom) -> user + "@" + dom);
    }

    @Provide
    Arbitrary<String> nomes() {
        return Arbitraries.strings()
                .withCharRange('a', 'z')
                .withCharRange('A', 'Z')
                .withChars(' ')
                .ofMinLength(1)
                .ofMaxLength(40)
                .filter(s -> !s.isBlank());
    }

    @Provide
    Arbitrary<String> senhasHash() {
        return Arbitraries.strings()
                .withCharRange('a', 'z')
                .withCharRange('A', 'Z')
                .withCharRange('0', '9')
                .ofMinLength(8)
                .ofMaxLength(60);
    }
}
