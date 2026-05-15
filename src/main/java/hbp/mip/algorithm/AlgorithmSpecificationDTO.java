package hbp.mip.algorithm;

import com.google.gson.annotations.SerializedName;

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
        ExaflowAlgorithmInputdataSpecificationDTO inputdata,
        Map<String, AlgorithmParameterSpecificationDTO> parameters,
        List<TransformerSpecificationDTO> preprocessing) {
    @Override
    public Map<String, AlgorithmParameterSpecificationDTO> parameters() {
        return Objects.requireNonNullElse(parameters, Collections.emptyMap());
    }

    @Override
    public List<TransformerSpecificationDTO> preprocessing() {
        return Objects.requireNonNullElse(preprocessing, Collections.emptyList());
    }

    public record AlgorithmParameterSpecificationDTO(
            String label,
            String desc,
            List<String> types,
            String required,
            String multiple,
            String min,
            String max,
            @SerializedName("default") String default_value,
            AlgorithmEnumDTO enums,
            AlgorithmEnumDTO dict_keys_enums,
            AlgorithmEnumDTO dict_values_enums,
            String dict_values_type

    ) {
        public record AlgorithmEnumDTO(
                String type,
                List<String> source) {
        }
    }

    public record ExaflowAlgorithmInputdataSpecificationDTO(
            AlgorithmInputDataDetailSpecificationDTO x,
            AlgorithmInputDataDetailSpecificationDTO y,
            AlgorithmInputDataDetailSpecificationDTO data_model,
            AlgorithmInputDataDetailSpecificationDTO datasets,
            AlgorithmInputDataDetailSpecificationDTO validation_datasets,
            AlgorithmInputDataDetailSpecificationDTO filter) {
    }

    public record AlgorithmInputDataDetailSpecificationDTO(
            String label,
            String desc,
            List<String> types,
            List<String> stattypes,
            String required,
            Integer min_count,
            Integer max_count

    ) {
    }

    public record TransformerSpecificationDTO(
            String name,
            String label,
            String desc,
            String documentation,
            Integer order,
            Map<String, AlgorithmParameterSpecificationDTO> parameters) {
        @Override
        public Map<String, AlgorithmParameterSpecificationDTO> parameters() {
            return Objects.requireNonNullElse(parameters, Collections.emptyMap());
        }
    }
}
