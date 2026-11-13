package dev.gilberto.gestaousuarios.usuario;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Cadastro público: não aceita {@code perfil}; um campo {@code perfil} enviado é ignorado. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UsuarioRequest(
        @NotBlank(message = "{email.obrigatorio}")
        @Email(message = "{email.invalido}")
        String email,
        @NotBlank(message = "{nome.obrigatorio}")
        String nome,
        @NotBlank(message = "{password.obrigatorio}")
        @Size(min = 8, max = 64, message = "{password.tamanho}")
        String senha
){}
