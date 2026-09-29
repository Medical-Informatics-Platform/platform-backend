package hbp.mip.algorithm;

import java.util.List;

public record InputDataSpecificationDTO(
        String label,
        String desc,
        List<String> types,
        List<String> stattypes,
        Boolean required,
        Integer min_count,
        Integer max_count) {
}
