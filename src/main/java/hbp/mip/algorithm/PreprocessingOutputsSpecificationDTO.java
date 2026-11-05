package hbp.mip.algorithm;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Exaflow serializes unset output fields as explicit nulls; ALWAYS keeps them through the
 * application-wide {@code non_null} Jackson inclusion.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record PreprocessingOutputsSpecificationDTO(
        String new_column_names_param,
        List<Column> columns) {
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record Column(
            String type,
            String stattype,
            String column_count_param,
            Enumerations enumerations) {
    }

    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record Enumerations(
            String source_parameter_name,
            String source_type,
            String additional_value_parameter_name,
            String prefix_parameter_name) {
    }
}
