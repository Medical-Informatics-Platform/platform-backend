package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisRequestDTO;

public record ExperimentExecutionDTO(
        String name,
        AnalysisRequestDTO analysis) {
}
