package hbp.mip.experiment;

import hbp.mip.user.UserDAO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ExperimentNotFoundException;
import hbp.mip.utils.Logger;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.CrudRepository;

import java.util.UUID;

public interface ExperimentRepository
        extends CrudRepository<ExperimentDAO, UUID>, JpaSpecificationExecutor<ExperimentDAO> {
    ExperimentDAO findByUuid(UUID experimentUuid);

    static UUID parseUuid(String uuid, Logger logger) {
        try {
            return UUID.fromString(uuid);
        } catch (IllegalArgumentException e) {
            logger.error("Conversion of string to UUID failed:" + e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
    }

    default ExperimentDAO loadExperiment(String uuid, Logger logger) {
        UUID experimentUuid = parseUuid(uuid, logger);

        ExperimentDAO experimentDAO = findByUuid(experimentUuid);
        if (experimentDAO == null) {
            var errorMessage = "Experiment with uuid : " + uuid + "was not found.";
            logger.warn(errorMessage);
            throw new ExperimentNotFoundException(errorMessage);
        }

        return experimentDAO;
    }

    /**
     * Persists a kept run as a finished experiment. Everything describing the run (analysis, result,
     * when it started and finished, which MIP version computed it) is copied unchanged; only the
     * identity, owner and name are new, so one run can be saved more than once.
     */
    default ExperimentDAO createExperimentFromRun(ExperimentRunDAO run, String name, UserDTO user,
            Logger logger) {
        ExperimentDAO experimentDAO = new ExperimentDAO();

        experimentDAO.setUuid(UUID.randomUUID());
        experimentDAO.setCreatedBy(new UserDAO(user));
        experimentDAO.setAnalysis(run.getAnalysis());
        experimentDAO.setAlgorithmId(run.getAlgorithmId());
        experimentDAO.setName(name);
        experimentDAO.setMipVersion(run.getMipVersion());
        experimentDAO.setStatus(ExperimentDAO.Status.success);
        experimentDAO.setResult(run.getResult());
        experimentDAO.setCreated(run.getCreated());
        experimentDAO.setFinished(run.getFinished());

        try {
            save(experimentDAO);
        } catch (Exception e) {
            logger.error("Failed to save to the database: " + e.getMessage());
            throw e;
        }
        return experimentDAO;
    }
}
