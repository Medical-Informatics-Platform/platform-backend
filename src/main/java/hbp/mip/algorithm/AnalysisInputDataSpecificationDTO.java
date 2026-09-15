package hbp.mip.algorithm;

public record AnalysisInputDataSpecificationDTO(
        InputDataSpecificationDTO data_model,
        InputDataSpecificationDTO datasets,
        InputDataSpecificationDTO filters,
        InputDataSpecificationDTO variables,
        InputDataSpecificationDTO validation_datasets) {
}
