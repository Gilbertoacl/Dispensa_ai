package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class UsuarioResponseCamposPropertyTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().findAndAddModules().build();

    // Feature: endurecimento-autenticacao, Property 20: UsuarioResponse expõe exatamente os campos públicos
    // Validates: Requirements 14.1, 14.2
    @Property(tries = 200)
    void respostaExpoeExatamenteOsCamposPublicos(@ForAll("locais") String local,
                                                 @ForAll("nomes") String nome,
                                                 @ForAll("hashes") String senhaHash,
                                                 @ForAll Perfil perfil,
                                                 @ForAll("tokenVersions") int tokenVersion) throws Exception {
        Usuario u = new Usuario(local + "@example.com", nome, senhaHash, perfil);
        definir(u, "id", UUID.randomUUID());
        definir(u, "tokenVersion", tokenVersion);

        UsuarioResponse resp = new UsuarioResponse(u.getId(), u.getEmail(), u.getNome(), u.getPerfil(),
                u.getDataCriacao());
        String json = MAPPER.writeValueAsString(resp);
        JsonNode no = MAPPER.readTree(json);

        Set<String> chaves = new TreeSet<>();
        no.propertyNames().forEach(chaves::add);
        assertThat(chaves).containsExactlyInAnyOrder("id", "email", "nome", "perfil", "dataDeCriacao");

        assertThat(no.get("id").asString()).isEqualTo(u.getId().toString());
        assertThat(no.get("email").asString()).isEqualTo(u.getEmail());
        assertThat(no.get("nome").asString()).isEqualTo(u.getNome());
        assertThat(no.get("perfil").asString()).isEqualTo(perfil.name());
        assertThat(no.get("dataDeCriacao").isNull()).isFalse();

        // os nomes de propriedade já foram verificados exatamente; o valor do hash nunca aparece no texto
        assertThat(json).doesNotContain(senhaHash).doesNotContain("\"senhaHash\"").doesNotContain("\"tokenVersion\"")
                .doesNotContain("\"refreshToken\"");
    }

    private static void definir(Usuario u, String campo, Object valor) throws ReflectiveOperationException {
        Field f = Usuario.class.getDeclaredField(campo);
        f.setAccessible(true);
        f.set(u, valor);
    }

    @Provide
    Arbitrary<String> locais() {
        return Arbitraries.strings().withCharRange('a', 'z').withCharRange('0', '9').ofMinLength(1).ofMaxLength(12);
    }

    @Provide
    Arbitrary<String> nomes() {
        return Arbitraries.strings().withCharRange('A', 'Z').withCharRange('a', 'z').ofMinLength(1).ofMaxLength(30);
    }

    @Provide
    Arbitrary<String> hashes() {
        return Arbitraries.strings().withCharRange('a', 'z').withCharRange('A', 'Z').withCharRange('0', '9')
                .ofMinLength(20).ofMaxLength(60).map(s -> "$2a$10$" + s);
    }

    @Provide
    Arbitrary<Integer> tokenVersions() {
        return Arbitraries.integers().between(0, 1000);
    }
}
