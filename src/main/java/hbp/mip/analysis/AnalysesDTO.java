package hbp.mip.analysis;

import java.util.List;

public record AnalysesDTO(
        List<AnalysisDTO> analyses,
        Integer currentPage,
        Integer totalPages,
        Long totalAnalyses
) {
}
