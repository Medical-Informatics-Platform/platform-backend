package hbp.mip;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import tools.jackson.databind.json.JsonMapper;

import java.util.concurrent.atomic.AtomicReference;

/**
 * The JSON mapper Spring MVC uses for request and response bodies, configured from application.yml
 * (including {@code spring.jackson.default-property-inclusion}). Tests that pin what the UI sends or
 * receives use it instead of a plain ObjectMapper, which does not see that configuration.
 */
public final class SpringJsonMapper {
    public static final JsonMapper INSTANCE = create();

    private SpringJsonMapper() {
    }

    private static JsonMapper create() {
        AtomicReference<JsonMapper> mapper = new AtomicReference<>();
        new ApplicationContextRunner()
                .withInitializer(new ConfigDataApplicationContextInitializer())
                .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class))
                .run(context -> mapper.set(context.getBean(JsonMapper.class)));
        return mapper.get();
    }
}
