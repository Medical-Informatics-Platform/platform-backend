package hbp.mip.analysis;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.RawJson;

import java.util.Date;
import java.util.UUID;

public record AnalysisDTO(
        UUID uuid,
        String name,
        UserDTO createdBy,
        Date created,
        Date updated,
        Date finished,
        Boolean shared,
        Boolean viewed,
        Object result,
        AnalysisDAO.Status status,
        AnalysisRequestDTO analysisRequest,
        String mipVersion) {
    public AnalysisDTO(AnalysisDAO analysisDAO, boolean includeResult) {
        this(
                analysisDAO.getUuid(),
                analysisDAO.getName(),
                new UserDTO(analysisDAO.getCreatedBy()),
                analysisDAO.getCreated(),
                analysisDAO.getUpdated(),
                analysisDAO.getFinished(),
                analysisDAO.isShared(),
                analysisDAO.isViewed(),
                includeResult && analysisDAO.getResult() != null ? new RawJson(analysisDAO.getResult()) : null,
                analysisDAO.getStatus(),
                AnalysisRequestDTO.fromStored(analysisDAO.getAnalysisRequest()),
                analysisDAO.getMipVersion());
    }
}
