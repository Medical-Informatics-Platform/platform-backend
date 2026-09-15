package hbp.mip.algorithm;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record AlgorithmSpecificationDTO(
        String name,
        String label,
        String desc,
        String documentation,
        String type,
        List<String> flags,
        InputDataSpecificationDTO y,
        InputDataSpecificationDTO x,
        boolean requires_validation_datasets,
        Map<String, ParameterSpecificationDTO> parameters,
        List<String> required_preprocessing) {
    @Override
    public Map<String, ParameterSpecificationDTO> parameters() {
        return Objects.requireNonNullElse(parameters, Collections.emptyMap());
    }

    @Override
    public List<String> required_preprocessing() {
        return Objects.requireNonNullElse(required_preprocessing, Collections.emptyList());
    }
}
