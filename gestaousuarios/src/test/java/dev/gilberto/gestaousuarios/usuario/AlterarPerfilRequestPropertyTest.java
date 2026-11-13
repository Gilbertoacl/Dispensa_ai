package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class AlterarPerfilRequestPropertyTest {

    private static final Validator VALIDATOR;

    static {
        try (ValidatorFactory f = Validation.buildDefaultValidatorFactory()) {
            VALIDATOR = f.getValidator();
        }
    }

    // Feature: endurecimento-autenticacao, Property 10: Validação do valor de perfil
    // Validates: Requirements 7.2
    @Property(tries = 300)
    void somenteAdminEUserSaoValidos(@ForAll("valores") String valor) {
        Set<ConstraintViolation<AlterarPerfilRequest>> violacoes =
                VALIDATOR.validate(new AlterarPerfilRequest(valor));

        boolean valido = "ADMIN".equals(valor) || "USER".equals(valor);
        if (valido) {
            assertThat(violacoes).isEmpty();
        } else {
            assertThat(violacoes).isNotEmpty();
            assertThat(violacoes).allSatisfy(v -> {
                assertThat(v.getPropertyPath().toString()).isEqualTo("perfil");
                assertThat(v.getMessageTemplate()).isEqualTo("{perfil.invalido}");
            });
        }
    }

    @Provide
    Arbitrary<String> valores() {
        Arbitrary<String> variacoesDeCaixa = Arbitraries.of("admin", "user", "Admin", "User", "aDMIN", "uSER",
                "ADMIN ", " USER", "ADMIN\n", "ROLE_ADMIN", "USERS");
        Arbitrary<String> caixaAleatoria = Arbitraries.of("ADMIN", "USER").flatMap(base ->
                Arbitraries.integers().between(0, (1 << base.length()) - 1).map(mascara -> {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < base.length(); i++) {
                        char c = base.charAt(i);
                        sb.append(((mascara >> i) & 1) == 1 ? Character.toLowerCase(c) : c);
                    }
                    return sb.toString();
                }));
        return Arbitraries.oneOf(
                Arbitraries.of("ADMIN", "USER"),
                Arbitraries.just((String) null),
                Arbitraries.of("", " ", "   ", "\t", "\n"),
                variacoesDeCaixa,
                caixaAleatoria,
                Arbitraries.strings().ofMaxLength(20));
    }
}
