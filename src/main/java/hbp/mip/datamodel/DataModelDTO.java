package hbp.mip.datamodel;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

public record DataModelDTO(
        String code,
        String version,
        String label,
        Boolean longitudinal,
        List<CommonDataElementDTO> variables,
        List<DataModelGroupDTO> groups,
        List<DataModelDTO.EnumerationDTO> datasets,
        Map<String, List<String>> datasetsVariables
) {

    public record DataModelGroupDTO(
            String code,
            String label,
            List<CommonDataElementDTO> variables,
            List<DataModelGroupDTO> groups
    ) {
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CommonDataElementDTO {
        private String code;
        private String label;
        private String description;
        private String sql_type;
        private String is_categorical;
        @Setter
        private List<DataModelDTO.EnumerationDTO> enumerations;
        private String minValue;
        private String maxValue;
        private String type;
        private String methodology;
        private String units;
    }

    public record EnumerationDTO(String code, String label) {
    }
}
