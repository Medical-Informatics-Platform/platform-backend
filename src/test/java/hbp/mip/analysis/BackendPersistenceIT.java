package hbp.mip.analysis;

import hbp.mip.algorithm.AnalysisExecutionService;
import hbp.mip.configurations.PersistenceConfiguration;
import hbp.mip.study.*;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Exceptions.AnalysisNotFoundException;
import hbp.mip.utils.Exceptions.ConflictException;
import hbp.mip.utils.Exceptions.UnauthorizedException;
import hbp.mip.utils.Logger;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindingPostProcessor;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.security.authentication.TestingAuthenticationToken;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** Real PostgreSQL only. Old names below describe the immutable V5 migration fixture. */
class BackendPersistenceIT {
    private static final String REQUEST = """
            { "request_id":"historic-id", "inputdata":{"data_model":"dm:1","datasets":["DS1"],
              "validation_datasets":["DS2"],"variables":["age"],"filters":{"condition":"AND"}},
              "preprocessing":[{"name":"scale","parameters":{"method":"standard"}}],
              "algorithm":{"name":"histogram","x":["age"],"parameters":{"bins":10}},"flags":{"option":true} }
            """;
    private static final String RESULT = "{ \"n_obs\":217, \"p\":null, \"large\":9007199254740993, \"table\":{\"se\":null} }";
    private static final String SIMPLE_REQUEST = "{\"inputdata\":{\"datasets\":[\"ds1\"]},\"algorithm\":{\"name\":\"histogram\"}}";
    private static final Logger LOGGER = new Logger("owner", "integration-test");

    private DriverManagerDataSource database;
    private DriverManagerDataSource scopedDatabase;
    private JdbcTemplate jdbc;
    private String schema;
    private AnnotationConfigApplicationContext context;
    private final AnalysisExecutionService execution = mock(AnalysisExecutionService.class);

    @BeforeEach
    void createIsolatedSchema() {
        String url = Objects.requireNonNull(System.getProperty("it.database.url"), "Use -Ppostgres-integration");
        String username = System.getProperty("it.database.username");
        String password = System.getProperty("it.database.password");
        database = new DriverManagerDataSource(url, username, password);
        schema = "terminology_" + UUID.randomUUID().toString().replace("-", "");
        new JdbcTemplate(database).execute("CREATE SCHEMA " + schema);
        scopedDatabase = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema,
                username, password);
        jdbc = new JdbcTemplate(scopedDatabase);
    }

    @AfterEach
    void removeIsolatedSchema() {
        if (context != null) {
            context.close();
        }
        if (database != null && schema != null) {
            new JdbcTemplate(database).execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }

    @Test
    void freshDatabaseMigratesAndStartsTheRealJpaConfiguration() {
        migrate(null);
        startContext();
        assertThat(context.getBean(AnalysisRepository.class).count()).isZero();
        assertThat(context.getBean(AnalysisRunRepository.class).count()).isZero();
        assertThat(context.getBean(StudyRepository.class).count()).isZero();
        assertNoObsoleteSchemaObjects();
        assertThat(jdbc.queryForObject("SELECT proargnames[1] FROM pg_proc WHERE oid = "
                + "'analysis_datasets_readable(text,text)'::regprocedure", String.class)).isEqualTo("analysis_request");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM flyway_schema_history WHERE success", Integer.class))
                .isEqualTo(6);
    }

    @Test
    void populatedUpgradePreservesEveryValueAndAllMembershipOrderings() {
        migrate("5");
        seedV5();
        var records = snapshot("experiment", "uuid");
        var drafts = snapshot("experiment_run", "uuid");
        var studies = snapshot("experiment_folder", "id");
        var groups = snapshot("experiment_set", "id");
        var members = snapshot("experiment_folder_member", "id");

        migrate(null);

        assertThat(snapshot("analysis", "uuid")).isEqualTo(records);
        assertThat(snapshot("analysis_run", "uuid")).isEqualTo(drafts);
        assertThat(snapshot("study", "id")).isEqualTo(studies);
        assertThat(snapshot("analysis_group", "id")).isEqualTo(groups);
        assertThat(snapshot("study_member", "id")).isEqualTo(members);
        assertNoObsoleteSchemaObjects();
        startContext();
        var study = context.getBean(StudyService.class).getStudy(principal("owner"), id(101).toString(), LOGGER);
        assertThat(study.analysisIds()).containsExactly(id(2).toString(), id(1).toString(), id(3).toString());
        assertThat(study.groups()).singleElement().satisfies(group -> {
            assertThat(group.id()).isEqualTo(id(111).toString());
            assertThat(group.analysisIds()).containsExactly(id(2).toString(), id(1).toString());
        });
    }

    @Test
    void renamedFunctionMakesExactlyTheSameDatasetDecisionsAsV5() {
        migrate("5");
        var requests = Arrays.asList(REQUEST, SIMPLE_REQUEST, null, "", "not JSON", "{}", "null", "[]",
                "{\"inputdata\":{\"datasets\":[]}}", "{\"inputdata\":{\"datasets\":\"ds1\"}}",
                "{\"inputdata\":{\"datasets\":[\"DS1\"],\"validation_datasets\":null}}",
                "{\"inputdata\":{\"datasets\":[\"ds1\"],\"validation_datasets\":\"ds2\"}}",
                "{\"inputdata\":{\"datasets\":[null]}}");
        var allowed = Arrays.asList("[]", "[\"ds1\"]", "[\"ds1\",\"ds2\"]", "[\"DS1\"]", null, "invalid JSON");
        List<Boolean> before = new ArrayList<>();
        requests.forEach(request -> allowed.forEach(grants -> before.add(readable("experiment", request, grants))));
        assertThat(readable("experiment", REQUEST, "[\"ds1\",\"ds2\"]")).isTrue();
        assertThat(readable("experiment", REQUEST, "[\"ds1\"]")).isFalse();

        migrate(null);

        List<Boolean> after = new ArrayList<>();
        requests.forEach(request -> allowed.forEach(grants -> after.add(readable("analysis", request, grants))));
        assertThat(after).containsExactlyElementsOf(before);
    }

    @Test
    void migratedRunsQueriesAndStudyOperationsKeepTheirBehavior() {
        migrate("5");
        seedV5();
        migrate(null);
        startContext();
        var analyses = context.getBean(AnalysisService.class);
        var repository = context.getBean(AnalysisRepository.class);

        var first = analyses.saveAnalysisRun(user("owner"), id(20).toString(), "Saved", LOGGER);
        var second = analyses.saveAnalysisRun(user("owner"), id(20).toString(), "Saved again", LOGGER);
        assertThat(first.uuid()).isNotEqualTo(second.uuid()).isNotEqualTo(id(20));
        var saved = repository.findByUuid(first.uuid());
        var draft = context.getBean(AnalysisRunRepository.class).findById(id(20)).orElseThrow();
        assertThat(saved.getAnalysisRequest()).isEqualTo(REQUEST);
        assertThat(saved.getResult()).isEqualTo(RESULT);
        assertThat(saved.getCreated()).isEqualTo(draft.getCreated());
        assertThat(saved.getFinished()).isEqualTo(draft.getFinished());
        assertThat(saved.getMipVersion()).isEqualTo("historic-version");
        assertThat(saved.getCreatedBy().getUsername()).isEqualTo("owner");
        assertThat(saved.isShared()).isFalse();
        assertThat(context.getBean(AnalysisRunRepository.class).count()).isEqualTo(3);
        verifyNoInteractions(execution);
        for (int unavailable : List.of(21, 22)) {
            assertThatThrownBy(() -> analyses.saveAnalysisRun(user("owner"), id(unavailable).toString(), "No", LOGGER))
                    .isInstanceOf(AnalysisNotFoundException.class);
        }

        var reader = principal("reader", "research_dataset_ds1");
        var page = analyses.getAnalyses(reader, null, null, null, null, true, false, false,
                0, 1, "created", true, LOGGER);
        assertThat(page.totalAnalyses()).isEqualTo(2);
        assertThat(page.totalPages()).isEqualTo(2);
        assertThat(page.analyses()).hasSize(1);
        assertThatThrownBy(() -> analyses.getAnalysis(reader, id(1).toString(), LOGGER))
                .isInstanceOf(UnauthorizedException.class);
        assertThat(analyses.getAnalysis(principal("reader", "research_dataset_ds1", "research_dataset_ds2"),
                id(1).toString(), LOGGER).uuid()).isEqualTo(id(1));
        assertThat(analyses.getAnalysis(principal("reader", "research_experiment_all"), id(3).toString(), LOGGER).uuid())
                .isEqualTo(id(3));
        assertThatThrownBy(() -> analyses.deleteAnalysis(user("reader"), id(2).toString(), LOGGER))
                .isInstanceOf(UnauthorizedException.class);

        var studies = context.getBean(StudyService.class);
        var owner = principal("owner");
        assertThatThrownBy(() -> studies.createStudy(owner, new CreateStudyDTO("  FIRST   study ", null), LOGGER))
                .isInstanceOf(ConflictException.class);
        var initial = studies.getStudy(owner, id(101).toString(), LOGGER);
        assertThat(studies.addAnalysis(owner, id(101).toString(), new AddStudyMemberDTO(id(1).toString()), LOGGER))
                .isEqualTo(initial);
        var moved = studies.updateGroupMembership(owner, id(102).toString(), id(1).toString(),
                new UpdateAnalysisGroupMembershipDTO(null), LOGGER);
        assertThat(moved.analysisIds()).contains(id(1).toString());
        assertThat(moved.groups().getFirst().analysisIds()).isEmpty();
        assertThat(studies.getStudy(owner, id(101).toString(), LOGGER).groups().getFirst().analysisIds())
                .contains(id(1).toString());
        var ungrouped = studies.deleteGroup(owner, id(101).toString(), id(111).toString(), LOGGER);
        assertThat(ungrouped.analysisIds()).containsExactlyElementsOf(initial.analysisIds());
        assertThat(ungrouped.groups()).isEmpty();
        studies.deleteStudy(owner, id(101).toString(), LOGGER);
        assertThat(repository.findByUuid(id(1))).isNotNull();
        assertThat(studies.getStudy(owner, id(102).toString(), LOGGER).analysisIds()).contains(id(1).toString());
        analyses.deleteAnalysis(user("owner"), id(1).toString(), LOGGER);
        assertThat(studies.getStudy(owner, id(102).toString(), LOGGER).analysisIds()).isEmpty();
    }

    private void migrate(String target) {
        var configuration = Flyway.configure().dataSource(scopedDatabase).schemas(schema).defaultSchema(schema);
        if (target != null) {
            configuration.target(MigrationVersion.fromVersion(target));
        }
        configuration.load().migrate();
    }

    private void startContext() {
        context = new AnnotationConfigApplicationContext();
        context.getBeanFactory().setConversionService(ApplicationConversionService.getSharedInstance());
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("integration", Map.of(
                "spring.datasource.url", scopedDatabase.getUrl(),
                "spring.datasource.username", System.getProperty("it.database.username"),
                "spring.datasource.password", System.getProperty("it.database.password"),
                "authentication.enabled", "true",
                "authentication.all_analyses_allowed_claim", "research_experiment_all",
                "authentication.all_datasets_allowed_claim", "research_dataset_all",
                "authentication.dataset_claim_prefix", "research_dataset_",
                "mip.version", "current-version", "analyses.run-draft-ttl", "PT24H")));
        ConfigurationPropertiesBindingPostProcessor.register(context);
        context.getBeanFactory().addBeanPostProcessor(new BeanPostProcessor() {
            @Override
            public Object postProcessBeforeInitialization(Object bean, String name) {
                if (bean instanceof LocalContainerEntityManagerFactoryBean factory) {
                    factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "validate"));
                }
                return bean;
            }
        });
        var users = mock(ActiveUserService.class);
        when(users.getActiveUser(any())).thenAnswer(call -> user(call.<org.springframework.security.core.Authentication>getArgument(0).getName()));
        context.registerBean(ActiveUserService.class, () -> users);
        context.registerBean(AnalysisExecutionService.class, () -> execution);
        context.register(PersistenceConfiguration.class, ClaimUtils.class, AnalysisService.class, StudyService.class);
        context.refresh();
    }

    private void seedV5() {
        for (String username : List.of("owner", "reader", "other")) {
            jdbc.update("INSERT INTO \"user\" (username, subject_id, agree_nda) VALUES (?, ?, true)", username, username + "-subject");
        }
        for (int n = 1; n <= 7; n++) {
            String owner = n == 4 ? "reader" : n == 5 ? "other" : "owner";
            String request = switch (n) {
                case 1 -> REQUEST;
                case 2, 3 -> SIMPLE_REQUEST;
                case 5 -> "{}";
                case 7 -> null;
                default -> "historic serialization error";
            };
            jdbc.update("INSERT INTO experiment (uuid,name,created_by_username,status,result,finished,analysis,algorithm_id,"
                            + "created,updated,shared,viewed,mip_version) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP,?,?,"
                            + "CURRENT_TIMESTAMP - interval '3 hours',CURRENT_TIMESTAMP,?,?,?)",
                    id(n), "Historical " + n, owner, n == 3 ? "pending" : n == 6 ? "error" : "success",
                    RESULT, request, "histogram", n != 3 && n != 4, n == 2, "historic-version");
        }
        for (int n = 20; n <= 22; n++) {
            jdbc.update("INSERT INTO experiment_run (uuid,created_by_username,result,analysis,algorithm_id,created,finished,mip_version) "
                            + "VALUES (?,?,?,?,?,CURRENT_TIMESTAMP - (? * interval '1 hour'),CURRENT_TIMESTAMP,?)",
                    id(n), n == 22 ? "other" : "owner", RESULT, REQUEST, "histogram", n == 21 ? 25 : 2, "historic-version");
        }
        jdbc.update("INSERT INTO experiment_folder (id,owner_username,name,sort_order) VALUES (?, 'owner', 'First study', 7),"
                + "(?, 'owner', 'Second study', 2)", id(101), id(102));
        jdbc.update("INSERT INTO experiment_set (id,folder_id,name,sort_order) VALUES (?, ?, 'First group', 5),"
                + "(?, ?, 'Second group', 3)", id(111), id(101), id(112), id(102));
        jdbc.update("INSERT INTO experiment_folder_member (id,folder_id,experiment_uuid,set_id,folder_position,set_position) "
                + "VALUES (?, ?, ?, ?, 8, 3),(?, ?, ?, ?, 4, 1),(?, ?, ?, NULL, 10, NULL),(?, ?, ?, ?, 9, 1)",
                id(121), id(101), id(1), id(111), id(122), id(101), id(2), id(111),
                id(123), id(101), id(3), id(124), id(102), id(1), id(112));
    }

    private List<List<Object>> snapshot(String table, String key) {
        // PostgreSQL column renames preserve column order, so this compares every value, including nulls.
        return jdbc.query("SELECT * FROM " + table + " ORDER BY " + key, (row, index) -> {
            List<Object> values = new ArrayList<>();
            for (int column = 1; column <= row.getMetaData().getColumnCount(); column++) {
                values.add(row.getObject(column));
            }
            return values;
        });
    }

    private Boolean readable(String prefix, String request, String allowed) {
        return jdbc.queryForObject("SELECT " + prefix + "_datasets_readable(?::text, ?::text)", Boolean.class, request, allowed);
    }

    private void assertNoObsoleteSchemaObjects() {
        assertThat(jdbc.queryForList("SELECT tablename FROM pg_tables WHERE schemaname = ? AND tablename LIKE '%experiment%'",
                String.class, schema)).isEmpty();
        assertThat(jdbc.queryForList("SELECT indexname FROM pg_indexes WHERE schemaname = ? AND indexname LIKE '%experiment%'",
                String.class, schema)).isEmpty();
        assertThat(jdbc.queryForList("SELECT conname FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
                + "WHERE n.nspname = ? AND conname LIKE '%experiment%'", String.class, schema)).isEmpty();
        assertThat(jdbc.queryForObject("SELECT to_regprocedure('experiment_datasets_readable(text,text)')", String.class)).isNull();
    }

    private static UUID id(int number) {
        return UUID.nameUUIDFromBytes(("fixture-" + number).getBytes(StandardCharsets.UTF_8));
    }

    private static UserDTO user(String username) {
        return new UserDTO(username, username, username + "@example.org", username + "-subject", true);
    }

    private static TestingAuthenticationToken principal(String username, String... roles) {
        return new TestingAuthenticationToken(username, null, roles);
    }
}
