package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.algorithm.AnalysisService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.*;
import hbp.mip.utils.Exceptions.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.*;

import static hbp.mip.utils.JsonConverters.convertObjectToJsonString;

@Service
public class ExperimentService {

    private static final int MAX_PAGE_SIZE = 50;

    private final ActiveUserService activeUserService;
    private final ClaimUtils claimUtils;
    private final ExperimentRepository experimentRepository;
    private final AnalysisService analysisService;
    private final boolean authenticationIsEnabled;
    private final String mipVersion;

    public ExperimentService(
            ActiveUserService activeUserService,
            ClaimUtils claimUtils,
            ExperimentRepository experimentRepository,
            AnalysisService analysisService,
            @Value("${authentication.enabled}") boolean authenticationIsEnabled,
            @Value("${mip.version}") String mipVersion) {
        this.activeUserService = activeUserService;
        this.claimUtils = claimUtils;
        this.experimentRepository = experimentRepository;
        this.analysisService = analysisService;
        this.authenticationIsEnabled = authenticationIsEnabled;
        this.mipVersion = mipVersion;
    }

    public ExperimentsDTO getExperiments(Authentication authentication, String name, String algorithm, Boolean shared,
            Boolean viewed, boolean includeShared, boolean mine, boolean notMine, int page, int size, String orderBy,
            Boolean descending,
            Logger logger) {
        validatePageSize(size);

        Specification<ExperimentDAO> spec = buildExperimentSpecification(authentication, name, algorithm, shared,
                viewed, includeShared, mine, notMine, orderBy, descending, logger);
        Pageable pageable = PageRequest.of(page, size);
        Page<ExperimentDAO> experimentsPage = experimentRepository.findAll(spec, pageable);

        if (experimentsPage.isEmpty()) {
            throw new NoContent("No experiment found with the filters provided.");
        }

        return createExperimentsDTO(experimentsPage);
    }

    private void validatePageSize(int size) {
        if (size > MAX_PAGE_SIZE) {
            throw new BadRequestException("Invalid size input, max size is " + MAX_PAGE_SIZE);
        }
    }

    private Specification<ExperimentDAO> buildExperimentSpecification(Authentication authentication, String name,
            String algorithm, Boolean shared, Boolean viewed, boolean includeShared, boolean mine, boolean notMine,
            String orderBy,
            Boolean descending, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        boolean hasAccessRights = !authenticationIsEnabled
                || claimUtils.validateAccessRightsOnALLExperiments(authentication, logger);

        Specification<ExperimentDAO> spec;

        if (mine) {
            spec = Specification.where(new ExperimentSpecifications.MyExperiment(user.username()));
        } else if (notMine) {
            spec = Specification.where(new ExperimentSpecifications.NotMyExperiment(user.username()))
                    .and(new ExperimentSpecifications.SharedExperiment(true));
        } else if (hasAccessRights) {
            spec = (root, query, criteriaBuilder) -> criteriaBuilder.conjunction();
        } else {
            spec = Specification.where(new ExperimentSpecifications.MyExperiment(user.username()))
                    .or(new ExperimentSpecifications.SharedExperiment(includeShared));
        }

        return spec
                .and(new ExperimentSpecifications.ExperimentWithName(name))
                .and(new ExperimentSpecifications.ExperimentWithAlgorithm(algorithm))
                .and(new ExperimentSpecifications.ExperimentWithShared(shared))
                .and(new ExperimentSpecifications.ExperimentWithViewed(viewed))
                .and(new ExperimentSpecifications.ExperimentOrderBy(orderBy, descending));
    }

    private ExperimentsDTO createExperimentsDTO(Page<ExperimentDAO> pageExperiments) {
        List<ExperimentDTO> experiments = pageExperiments.map(experimentDAO -> new ExperimentDTO(experimentDAO, false))
                .getContent();
        return new ExperimentsDTO(experiments, pageExperiments.getNumber(), pageExperiments.getTotalPages(),
                pageExperiments.getTotalElements());
    }

    public ExperimentDTO getExperiment(Authentication authentication, String uuid, Logger logger) {
        ExperimentDAO experimentDAO = experimentRepository.loadExperiment(uuid, logger);
        validateExperimentAccess(authentication, experimentDAO, uuid, logger);

        return new ExperimentDTO(experimentDAO, true);
    }

    private void validateExperimentAccess(Authentication authentication, ExperimentDAO experimentDAO, String uuid,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        boolean unauthorizedAccess = authenticationIsEnabled && !experimentDAO.isShared()
                && !experimentDAO.getCreatedBy().getUsername().equals(user.username())
                && !claimUtils.validateAccessRightsOnALLExperiments(authentication, logger);

        if (unauthorizedAccess) {
            logger.warn("User tried to access an unauthorized experiment with id:" + uuid);
            throw new UnauthorizedException("You don't have access to that experiment.");
        }
    }

    public ExperimentDTO createExperiment(Authentication authentication, ExperimentExecutionDTO experimentExecutionDTO,
            Logger logger) {
        requireAnalysisPayload(experimentExecutionDTO, logger);
        analysisParametersLogging(experimentExecutionDTO, logger);

        validateDatasetAccess(authentication, experimentExecutionDTO, logger);

        ExperimentDAO experimentDAO = experimentRepository.createExperimentInTheDatabase(experimentExecutionDTO,
                activeUserService.getActiveUser(authentication), mipVersion, logger);
        runAnalysisInBackground(experimentDAO, experimentExecutionDTO, logger);

        return new ExperimentDTO(experimentDAO, false);
    }

    private void requireAnalysisPayload(ExperimentExecutionDTO experimentExecutionDTO, Logger logger) {
        if (experimentExecutionDTO.analysis() == null) {
            String errorMessage = "Missing required analysis payload.";
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
    }

    private void validateDatasetAccess(Authentication authentication, ExperimentExecutionDTO experimentExecutionDTO,
            Logger logger) {
        if (authenticationIsEnabled) {
            claimUtils.validateAccessRightsOnDatasets(authentication,
                    experimentExecutionDTO.analysis().inputdata().datasets(), logger);
        }
    }

    private void runAnalysisInBackground(ExperimentDAO experimentDAO, ExperimentExecutionDTO experimentExecutionDTO,
            Logger logger) {
        new Thread(() -> {
            try {
                logger.debug("Experiment analysis execution started in a background thread.");
                AnalysisService.AnalysisResultDTO resultDTO = analysisService.runAnalysis(
                        experimentDAO.getUuid(),
                        experimentExecutionDTO.analysis(),
                        logger);
                experimentDAO.setResult(convertObjectToJsonString(resultDTO.body()));
                experimentDAO
                        .setStatus(resultDTO.code() >= 400 ? ExperimentDAO.Status.error : ExperimentDAO.Status.success);
            } catch (Exception e) {
                logger.error("Exaflow analysis execution failed: " + e.getMessage());
                experimentDAO.setStatus(ExperimentDAO.Status.error);
            }
            experimentRepository.finishExperiment(experimentDAO, logger);
            logger.info("Experiment finished: " + experimentDAO);
        }).start();
    }

    public ExperimentDTO runTransientExperiment(Authentication authentication,
            ExperimentExecutionDTO experimentExecutionDTO, Logger logger) {
        requireAnalysisPayload(experimentExecutionDTO, logger);
        analysisParametersLogging(experimentExecutionDTO, logger);

        validateDatasetAccess(authentication, experimentExecutionDTO, logger);
        UUID uuid = UUID.randomUUID();
        AnalysisService.AnalysisResultDTO analysisResult = analysisService.runAnalysis(
                uuid,
                experimentExecutionDTO.analysis(),
                logger);

        return new ExperimentDTO(uuid, experimentExecutionDTO.name(), null, null, null, null, null, null,
                analysisResult.body(),
                analysisResult.code() >= 400 ? ExperimentDAO.Status.error : ExperimentDAO.Status.success,
                experimentExecutionDTO.analysis(),
                mipVersion);
    }

    public ExperimentDTO updateExperiment(UserDTO user, String uuid, ExperimentDTO experiment, Logger logger) {
        ExperimentDAO experimentDAO = experimentRepository.loadExperiment(uuid, logger);

        verifyNonEditableFieldsAreNotBeingModified(experiment, logger);
        checkUpdateAuthorization(user, experimentDAO, uuid, logger);

        updateModifiableFields(experiment, experimentDAO);
        experimentDAO.setUpdated(new Date());

        try {
            experimentRepository.save(experimentDAO);
        } catch (Exception e) {
            logger.error("Failed to save to the database: " + e.getMessage());
            throw new InternalServerError(e.getMessage());
        }

        return new ExperimentDTO(experimentDAO, true);
    }

    private void checkUpdateAuthorization(UserDTO user, ExperimentDAO experimentDAO, String uuid, Logger logger) {
        if (!experimentDAO.getCreatedBy().getUsername().equals(user.username())) {
            logger.warn("User tried to modify an unauthorized experiment with uuid: " + uuid);
            throw new UnauthorizedException("You don't have access to modify the experiment.");
        }
    }

    private void updateModifiableFields(ExperimentDTO experiment, ExperimentDAO experimentDAO) {
        if (experiment.name() != null && !experiment.name().isEmpty()) {
            experimentDAO.setName(experiment.name());
        }
        if (experiment.shared() != null) {
            experimentDAO.setShared(experiment.shared());
        }
        if (experiment.viewed() != null) {
            experimentDAO.setViewed(experiment.viewed());
        }
    }

    public void deleteExperiment(UserDTO user, String uuid, Logger logger) {
        ExperimentDAO experimentDAO = experimentRepository.loadExperiment(uuid, logger);

        checkDeleteAuthorization(user, experimentDAO, uuid, logger);

        try {
            experimentRepository.delete(experimentDAO);
        } catch (Exception e) {
            logger.info("Attempted to delete an experiment from the database but an error occurred: " + e.getMessage());
            throw new InternalServerError(e.getMessage());
        }
    }

    private void checkDeleteAuthorization(UserDTO user, ExperimentDAO experimentDAO, String uuid, Logger logger) {
        if (!experimentDAO.getCreatedBy().getUsername().equals(user.username())) {
            logger.warn("User " + user.username() + " tried to delete the experiment with uuid " + uuid
                    + " but was unauthorized.");
            throw new UnauthorizedException("You don't have access to delete the experiment.");
        }
    }

    private void verifyNonEditableFieldsAreNotBeingModified(ExperimentDTO experimentDTO, Logger logger) {
        throwIfNonNull(experimentDTO.uuid(), "uuid", logger);
        throwIfNonNull(experimentDTO.createdBy(), "createdBy", logger);
        throwIfNonNull(experimentDTO.created(), "created", logger);
        throwIfNonNull(experimentDTO.updated(), "updated", logger);
        throwIfNonNull(experimentDTO.finished(), "finished", logger);
        throwIfNonNull(experimentDTO.result(), "result", logger);
        throwIfNonNull(experimentDTO.status(), "status", logger);
        throwIfNonNull(experimentDTO.analysis(), "analysis", logger);
    }

    private void throwIfNonNull(Object field, String nonEditableField, Logger logger) {
        if (field != null) {
            String errorMessage = "Tried to edit non-editable field: " + nonEditableField;
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
    }

    private void analysisParametersLogging(ExperimentExecutionDTO experimentExecutionDTO, Logger logger) {
        AnalysisRequestDTO analysis = experimentExecutionDTO.analysis();
        StringBuilder parametersLogMessage = new StringBuilder();

        Optional.ofNullable(analysis.algorithm().parameters()).ifPresent(parameters -> parameters.forEach((paramName,
                paramValue) -> parametersLogMessage.append(" ").append(paramName).append(" -> ").append(paramValue)));

        Optional.ofNullable(analysis.preprocessing()).ifPresent(preprocessing -> preprocessing
                .forEach(step -> parametersLogMessage.append(" ").append(step.name()).append(" -> ")
                        .append(step.parameters())));

        if (analysis.inputdata() != null) {
            AnalysisRequestDTO.AnalysisInputDataDTO inputData = analysis.inputdata();
            parametersLogMessage.append(" Input Data Model: ").append(inputData.data_model());

            Optional.ofNullable(inputData.datasets())
                    .ifPresent(datasets -> parametersLogMessage.append(" Datasets: ").append(datasets));

            Optional.ofNullable(inputData.variables())
                    .ifPresent(variables -> parametersLogMessage.append(" Variables: ").append(variables));

            Optional.ofNullable(analysis.algorithm().x())
                    .ifPresent(xVars -> parametersLogMessage.append(" X Variables: ").append(xVars));

            Optional.ofNullable(analysis.algorithm().y())
                    .ifPresent(yVars -> parametersLogMessage.append(" Y Variables: ").append(yVars));

            if (inputData.filters() != null) {
                parametersLogMessage.append(" Filters: ").append(inputData.filters());
            }
        }

        logger.debug("Analysis " + analysis.algorithm().name() + " execution starting with parameters: "
                + parametersLogMessage);
    }
}
