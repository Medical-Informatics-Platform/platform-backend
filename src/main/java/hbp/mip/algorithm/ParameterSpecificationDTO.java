package hbp.mip.algorithm;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public record ParameterSpecificationDTO(
        String label,
        String desc,
        List<String> types,
        Boolean required,
        Boolean multiple,
        @SerializedName("default") Object default_value,
        ParameterEnumSpecificationDTO enums,
        ParameterEnumSpecificationDTO dict_keys_enums,
        ParameterEnumSpecificationDTO dict_values_enums,
        String dict_values_type,
        Double min,
        Double max) {
    public record ParameterEnumSpecificationDTO(
            String type,
            List<Object> source) {
    }
}
