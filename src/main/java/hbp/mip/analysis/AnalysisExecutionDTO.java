package hbp.mip.analysis;

import hbp.mip.algorithm.AnalysisRequestDTO;

public record AnalysisExecutionDTO(
        String name,
        AnalysisRequestDTO analysisRequest) {
}
