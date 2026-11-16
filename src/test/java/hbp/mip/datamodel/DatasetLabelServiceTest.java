package hbp.mip.datamodel;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class DatasetLabelServiceTest {

    @Test
    void readsTheDatasetEnumerationLabelsOfEveryDataModel() {
        DatasetLabels labels = DatasetLabelService.parse("""
                {"dementia:0.1": {"dataset": {"code": "dataset", "type": "nominal",
                                  "enumerations": {"12": "EDSD", "13": "PPMI"}},
                                  "age": {"code": "age", "type": "continuous", "enumerations": null}},
                 "tbi:0.1": {"dataset": {"code": "dataset", "enumerations": null}},
                 "empty:0.1": {"age": {"code": "age"}}}
                """);

        assertThat(labels.labelsFor("dementia:0.1", "12")).containsExactly("EDSD");
        assertThat(labels.labelsFor("dementia:0.1", "ppmi")).containsExactly("PPMI");
        assertThat(labels.labelsFor("tbi:0.1", "12")).isEmpty();
        assertThat(labels.labelsFor("empty:0.1", "12")).isEmpty();
        assertThat(labels.labelsFor("missing:0.1", "12")).isEmpty();
    }

    @Test
    void anEmptyOrBlankResponseResolvesNothing() {
        assertThat(DatasetLabelService.parse("")).isEqualTo(DatasetLabels.NONE);
        assertThat(DatasetLabelService.parse("{}").labelsFor("dementia:0.1", "12")).isEmpty();
    }

    @Test
    void keepsTheLabelsForTheTtlAndFailsClosedWhenTheyCannotBeRead() {
        int[] fetches = {0};
        boolean[] failing = {false};
        DatasetLabelService service = new DatasetLabelService("", "http://unused", Duration.ofHours(1)) {
            @Override
            String fetchBody() throws java.io.IOException {
                fetches[0]++;
                if (failing[0]) {
                    throw new java.io.IOException("down");
                }
                return "{\"m:1\":{\"dataset\":{\"enumerations\":{\"1\":\"A\"}}}}";
            }
        };
        hbp.mip.utils.Logger logger = new hbp.mip.utils.Logger("user", "test");

        assertThat(service.get(logger).labelsFor("m:1", "1")).containsExactly("A");
        failing[0] = true;
        assertThat(service.get(logger).labelsFor("m:1", "1")).containsExactly("A");
        assertThat(fetches[0]).isEqualTo(1);

        DatasetLabelService expired = new DatasetLabelService("", "http://unused", Duration.ZERO) {
            @Override
            String fetchBody() throws java.io.IOException {
                throw new java.io.IOException("down");
            }
        };
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> expired.get(logger))
                .isInstanceOf(hbp.mip.utils.Exceptions.InternalServerError.class);
    }
}
