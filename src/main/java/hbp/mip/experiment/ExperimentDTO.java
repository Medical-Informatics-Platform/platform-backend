package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.RawJson;

import java.util.Date;
import java.util.UUID;

public record ExperimentDTO(
        UUID uuid,
        String name,
        UserDTO createdBy,
        Date created,
        Date updated,
        Date finished,
        Boolean shared,
        Boolean viewed,
        Object result,
        ExperimentDAO.Status status,
        AnalysisRequestDTO analysis,
        String mipVersion) {
    public ExperimentDTO(ExperimentDAO experimentDAO, boolean includeResult) {
        this(
                experimentDAO.getUuid(),
                experimentDAO.getName(),
                new UserDTO(experimentDAO.getCreatedBy()),
                experimentDAO.getCreated(),
                experimentDAO.getUpdated(),
                experimentDAO.getFinished(),
                experimentDAO.isShared(),
                experimentDAO.isViewed(),
                includeResult && experimentDAO.getResult() != null ? new RawJson(experimentDAO.getResult()) : null,
                experimentDAO.getStatus(),
                JsonConverters.convertJsonStringToObject(experimentDAO.getAnalysis(), AnalysisRequestDTO.class),
                experimentDAO.getMipVersion());
    }
}
