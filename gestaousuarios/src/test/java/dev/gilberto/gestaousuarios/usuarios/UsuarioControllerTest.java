package dev.gilberto.gestaousuarios.usuarios;

import dev.gilberto.gestaousuarios.usuario.UsuarioController;
import dev.gilberto.gestaousuarios.usuario.UsuarioRequest;
import dev.gilberto.gestaousuarios.usuario.UsuarioResponse;
import dev.gilberto.gestaousuarios.usuario.UsuarioService;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UsuarioController.class)
class UsuarioControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UsuarioService usuarioService;

    private UsuarioRequest requestValido() {
        return new UsuarioRequest("mail@mail.com", "João das Neves", "123456789");
    }

    private UsuarioResponse responseValido() {
        return new UsuarioResponse("mail@mail.com", "João das Neves", Instant.now());
    }

    @Test
    void deveCriarUsuarioERetornar201() throws Exception {
        UsuarioRequest request = requestValido();
        when(usuarioService.criarUsuario(any(UsuarioRequest.class)))
                .thenReturn(responseValido());

        mockMvc.perform(post("/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(request.email()))
                .andExpect(jsonPath("$.nome").value(request.nome()));
    }

    @Test
    void deveRetornar400AoCriarUsuarioComEmailInvalido() throws Exception {
        UsuarioRequest request = new UsuarioRequest("emailinvalido", "João das Neves", "123456789");

        mockMvc.perform(post("/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}
