package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.testsupport.AuditoriaFalsa;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class SenhaRejeitadaPropertyTest {

    private static final String EMAIL = "pessoa@example.com";

    /** Senhas que violam ao menos uma regra da política (tamanho, bytes, igual ao e-mail, comum). */
    @Provide
    Arbitrary<String> senhasInvalidas() {
        Arbitrary<String> curtas = Arbitraries.strings().ofMinLength(0).ofMaxLength(7);
        Arbitrary<String> longas = Arbitraries.strings().alpha().ofMinLength(65).ofMaxLength(90);
        // 8 a 64 caracteres mas > 72 bytes UTF-8 (cada 'ã' ocupa 2 bytes): 37 a 64 caracteres
        Arbitrary<String> bytesExcedidos = Arbitraries.integers().between(37, 64)
                .map(n -> "ã".repeat(n));
        Arbitrary<String> igualAoEmail = Arbitraries.of(EMAIL, EMAIL.toUpperCase(Locale.ROOT),
                " " + EMAIL + " ", "Pessoa@Example.COM");
        Arbitrary<String> comuns = Combinators
                .combine(Arbitraries.of(PasswordPolicyProperties.PADRAO), Arbitraries.of(true, false))
                .as((s, maiuscula) -> maiuscula ? s.toUpperCase(Locale.ROOT) : s);
        return Arbitraries.oneOf(curtas, longas, bytesExcedidos, igualAoEmail, comuns);
    }

    // Feature: endurecimento-autenticacao, Property 19: Senha rejeitada não altera o estado
    // Validates: Requirements 13.8
    @Property(tries = 200)
    void criarUsuarioComSenhaRejeitadaNaoPersiste(@ForAll("senhasInvalidas") String senha) {
        UsuarioRepository repo = mock(UsuarioRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        EventoPublisher publisher = mock(EventoPublisher.class);
        when(repo.existsByEmail(EMAIL)).thenReturn(false);
        UsuarioService service = new UsuarioService(repo, encoder, publisher, PasswordPolicy.padrao(),
                RevogadorDeSessoes.semEfeito(), new AuditoriaFalsa());

        assertThatThrownBy(() -> service.criarUsuario(new UsuarioRequest(EMAIL, "Nome", senha)))
                .isInstanceOf(RegraNegocioException.class);

        verify(repo, never()).save(any());
        verify(repo, never()).saveAndFlush(any());
        verifyNoInteractions(encoder, publisher);
    }

    // Feature: endurecimento-autenticacao, Property 19: Senha rejeitada não altera o estado
    // Validates: Requirements 13.8
    @Property(tries = 200)
    void trocarSenhaComSenhaRejeitadaMantemHashTvESessoes(@ForAll("senhasInvalidas") String novaSenha) {
        UsuarioRepository repo = mock(UsuarioRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        RevogadorDeSessoes revogador = mock(RevogadorDeSessoes.class);
        AuditoriaFalsa auditoria = new AuditoriaFalsa();
        Usuario u = new Usuario(EMAIL, "Nome", "HASH_ORIGINAL", Perfil.USER);
        ReflectionTestUtils.setField(u, "id", UUID.randomUUID());
        when(repo.findById(u.getId())).thenReturn(Optional.of(u));
        when(encoder.matches("SenhaAtual#1", "HASH_ORIGINAL")).thenReturn(true);
        UsuarioService service = new UsuarioService(repo, encoder, null, PasswordPolicy.padrao(), revogador, auditoria);

        assertThatThrownBy(() -> service.trocarSenha(u.getId(), "SenhaAtual#1", novaSenha))
                .isInstanceOf(RegraNegocioException.class);

        assertThat(u.getSenhaHash()).isEqualTo("HASH_ORIGINAL");
        verify(repo, never()).save(any());
        verify(repo, never()).incrementarTokenVersion(any());
        verify(encoder, never()).encode(any());
        verifyNoInteractions(revogador);
        assertThat(auditoria.eventos()).isEqualTo(List.of());
    }
}
