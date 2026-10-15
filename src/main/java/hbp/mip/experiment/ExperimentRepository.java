package hbp.mip.experiment;

import hbp.mip.user.UserDAO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ExperimentNotFoundException;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.CrudRepository;

import java.util.Date;
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

    default ExperimentDAO createExperimentInTheDatabase(ExperimentExecutionDTO experimentExecutionDTO, UserDTO user,
            String mipVersion, Logger logger) {
        ExperimentDAO experimentDAO = new ExperimentDAO();
        UUID experimentUuid = UUID.randomUUID();

        experimentDAO.setUuid(experimentUuid);
        experimentDAO.setCreatedBy(new UserDAO(user));
        experimentDAO.setAlgorithm(JsonConverters.convertObjectToJsonString(experimentExecutionDTO.analysis()));
        experimentDAO.setAlgorithmId(experimentExecutionDTO.analysis().algorithm().name());
        experimentDAO.setName(experimentExecutionDTO.name());
        experimentDAO.setMipVersion(mipVersion);
        experimentDAO.setStatus(ExperimentDAO.Status.pending);

        try {
            save(experimentDAO);
        } catch (Exception e) {
            logger.error("Failed to save to the database: " + e.getMessage());
            throw e;
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
        experimentDAO.setAlgorithm(run.getAlgorithm());
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

    default void finishExperiment(ExperimentDAO experimentDAO, Logger logger) {
        experimentDAO.setFinished(new Date());

        try {
            save(experimentDAO);
        } catch (Exception e) {
            logger.error("Failed to save to the database: " + e.getMessage());
            throw e;
        }
    }
}
