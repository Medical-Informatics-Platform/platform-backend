package hbp.mip.analysis;

import hbp.mip.user.UserDAO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.AnalysisNotFoundException;
import hbp.mip.utils.Logger;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.CrudRepository;

import java.util.UUID;

public interface AnalysisRepository
        extends CrudRepository<AnalysisDAO, UUID>, JpaSpecificationExecutor<AnalysisDAO> {
    AnalysisDAO findByUuid(UUID analysisUuid);

    static UUID parseUuid(String uuid, Logger logger) {
        try {
            return UUID.fromString(uuid);
        } catch (IllegalArgumentException e) {
            logger.error("Conversion of string to UUID failed:" + e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
    }

    default AnalysisDAO loadAnalysis(String uuid, Logger logger) {
        UUID analysisUuid = parseUuid(uuid, logger);

        AnalysisDAO analysisDAO = findByUuid(analysisUuid);
        if (analysisDAO == null) {
            var errorMessage = "Analysis with uuid : " + uuid + "was not found.";
            logger.warn(errorMessage);
            throw new AnalysisNotFoundException(errorMessage);
        }

        return analysisDAO;
    }

    /**
     * Persists a kept run as a finished analysis. Everything describing the run (analysis, result,
     * when it started and finished, which MIP version computed it) is copied unchanged; only the
     * identity, owner and name are new, so one run can be saved more than once.
     */
    default AnalysisDAO createAnalysisFromRun(AnalysisRunDAO run, String name, UserDTO user,
            Logger logger) {
        AnalysisDAO analysisDAO = new AnalysisDAO();

        analysisDAO.setUuid(UUID.randomUUID());
        analysisDAO.setCreatedBy(new UserDAO(user));
        analysisDAO.setAnalysisRequest(run.getAnalysisRequest());
        analysisDAO.setAlgorithmId(run.getAlgorithmId());
        analysisDAO.setName(name);
        analysisDAO.setMipVersion(run.getMipVersion());
        analysisDAO.setStatus(AnalysisDAO.Status.success);
        analysisDAO.setResult(run.getResult());
        analysisDAO.setCreated(run.getCreated());
        analysisDAO.setFinished(run.getFinished());

        try {
            save(analysisDAO);
        } catch (Exception e) {
            logger.error("Failed to save to the database: " + e.getMessage());
            throw e;
        }
        return analysisDAO;
    }
}
