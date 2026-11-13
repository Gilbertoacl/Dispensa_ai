package dev.gilberto.gestaousuarios.usuario;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Testes do evento de domínio UsuarioCriado com publisher mockado (R16.1, R16.3).
 */
class UsuarioServiceEventoTest {

    @Test
    @DisplayName("deve publicar evento UsuarioCriado ao criar usuário, com email normalizado")
    void devePublicarEventoAoCriarUsuario() {
        UsuarioRepository usuarioRepository = mock(UsuarioRepository.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        EventoPublisher eventoPublisher = mock(EventoPublisher.class);
        UsuarioService service = new UsuarioService(usuarioRepository, passwordEncoder, eventoPublisher);

        when(usuarioRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("HASH");
        when(usuarioRepository.save(any(Usuario.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        UsuarioRequest req = new UsuarioRequest("  Fulano@Example.COM ", "Fulano", "Dispensa#2024");

        service.criarUsuario(req);

        ArgumentCaptor<UsuarioCriadoEvent> captor = ArgumentCaptor.forClass(UsuarioCriadoEvent.class);
        verify(eventoPublisher).publicarUsuarioCriado(captor.capture());

        UsuarioCriadoEvent evento = captor.getValue();
        assertThat(evento.email()).isEqualTo("fulano@example.com");
        assertThat(evento.dataCriacao()).isNotNull();
    }

    @Test
    @DisplayName("NoOpEventoPublisher não lança ao publicar evento")
    void noOpPublisherNaoLanca() {
        NoOpEventoPublisher publisher = new NoOpEventoPublisher();
        UsuarioCriadoEvent evento = new UsuarioCriadoEvent(
                java.util.UUID.randomUUID(), "fulano@example.com", java.time.Instant.now());

        assertThatCode(() -> publisher.publicarUsuarioCriado(evento)).doesNotThrowAnyException();
    }
}
