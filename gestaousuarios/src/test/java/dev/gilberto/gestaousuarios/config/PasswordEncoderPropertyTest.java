package dev.gilberto.gestaousuarios.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.CharRange;
import net.jqwik.api.constraints.StringLength;

/**
 * Testes de propriedade (jqwik) para o codificador de senha BCrypt (custo 12).
 */
class PasswordEncoderPropertyTest {

    // Feature: gestao-usuarios-autenticacao, Property 2: Round-trip de hashing BCrypt
    // Validates: Requirements 2.1, 2.2, 2.3
    @Property(tries = 100)
    void roundTripDeHashingBCrypt(
            @ForAll @StringLength(min = 8, max = 64) @CharRange(from = '!', to = '~') String senha) {
        PasswordEncoder encoder = new BCryptPasswordEncoder(12);

        String hash = encoder.encode(senha);

        // R2.2: o hash persistido nunca é a senha em texto plano
        assertThat(hash).isNotEqualTo(senha);

        // R2.3: a verificação BCrypt reconhece a senha correta
        assertThat(encoder.matches(senha, hash)).isTrue();

        // R2.3: uma senha distinta não corresponde ao hash
        String outra = senha + "X";
        assertThat(outra).isNotEqualTo(senha);
        assertThat(encoder.matches(outra, hash)).isFalse();
    }
}
