package hbp.mip.algorithm;

import java.util.List;

public record InputDataSpecificationDTO(
        String label,
        String desc,
        List<String> types,
        Boolean required,
        Integer min_count,
        Integer max_count) {
}
