package dev.gilberto.gestaousuarios.usuario;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UsuarioRequest(
        @NotBlank(message = "{email.obrigatorio}")
        @Email(message = "{email.invalido}")
        String email,
        @NotBlank(message = "{nome.obrigatorio}")
        String nome,
        @NotBlank(message = "{password.obrigatorio}")
        String senha
){}
