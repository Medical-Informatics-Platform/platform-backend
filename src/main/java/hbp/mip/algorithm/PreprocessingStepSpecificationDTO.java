package hbp.mip.algorithm;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

public record PreprocessingStepSpecificationDTO(
        String name,
        String desc,
        String documentation,
        String label,
        Map<String, ParameterSpecificationDTO> parameters,
        PreprocessingOutputSpecificationDTO output) {
    @Override
    public Map<String, ParameterSpecificationDTO> parameters() {
        return Objects.requireNonNullElse(parameters, Collections.emptyMap());
    }
}
