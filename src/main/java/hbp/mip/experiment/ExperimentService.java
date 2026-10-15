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

import java.time.Duration;
import java.util.*;

import static hbp.mip.utils.JsonConverters.convertObjectToJsonString;

@Service
public class ExperimentService {

    private static final int MAX_PAGE_SIZE = 50;

    private final ActiveUserService activeUserService;
    private final ClaimUtils claimUtils;
    private final ExperimentRepository experimentRepository;
    private final ExperimentRunRepository experimentRunRepository;
    private final AnalysisService analysisService;
    private final boolean authenticationIsEnabled;
    private final String mipVersion;
    private final Duration runDraftTtl;

    public ExperimentService(
            ActiveUserService activeUserService,
            ClaimUtils claimUtils,
            ExperimentRepository experimentRepository,
            ExperimentRunRepository experimentRunRepository,
            AnalysisService analysisService,
            @Value("${authentication.enabled}") boolean authenticationIsEnabled,
            @Value("${mip.version}") String mipVersion,
            @Value("${experiments.run-draft-ttl}") Duration runDraftTtl) {
        this.activeUserService = activeUserService;
        this.claimUtils = claimUtils;
        this.experimentRepository = experimentRepository;
        this.experimentRunRepository = experimentRunRepository;
        this.analysisService = analysisService;
        this.authenticationIsEnabled = authenticationIsEnabled;
        this.mipVersion = mipVersion;
        this.runDraftTtl = runDraftTtl;
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
        ExperimentDAO experimentDAO = assertExperimentAccessible(authentication, uuid, logger);

        return new ExperimentDTO(experimentDAO, true);
    }

    /**
     * Loads an experiment and refuses it when the active user may not read it, returning the entity so
     * other features can reference a run they are allowed to see.
     *
     * Feature code that only needs to know "is this run usable by this user" should call this instead
     * of reopening the access rules, which live in one place on purpose.
     */
    public ExperimentDAO assertExperimentAccessible(Authentication authentication, String uuid, Logger logger) {
        ExperimentDAO experimentDAO = experimentRepository.loadExperiment(uuid, logger);
        validateExperimentAccess(authentication, experimentDAO, uuid, logger);

        return experimentDAO;
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

    private void validateDatasetAccess(Authentication authentication, AnalysisRequestDTO analysis, Logger logger) {
        if (authenticationIsEnabled) {
            claimUtils.validateAccessRightsOnDatasets(authentication, analysis.inputdata().allDatasets(), logger);
        }
    }

    /** Runs an analysis and returns its result without storing anything. */
    public ExperimentDTO previewExperiment(Authentication authentication,
            ExperimentExecutionDTO experimentExecutionDTO, Logger logger) {
        AnalysisService.requireRunnable(experimentExecutionDTO.analysis(), logger);
        analysisParametersLogging(experimentExecutionDTO, logger);

        validateDatasetAccess(authentication, experimentExecutionDTO.analysis(), logger);
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

    /**
     * Runs an analysis like {@link #previewExperiment} and, when it succeeds, keeps the result so
     * {@link #saveExperimentRun} can persist it later without executing the analysis again. The
     * returned uuid is the run id to save.
     */
    public ExperimentDTO runExperiment(Authentication authentication, UserDTO user,
            ExperimentExecutionDTO experimentExecutionDTO, Logger logger) {
        Date started = new Date();
        ExperimentDTO run = previewExperiment(authentication, experimentExecutionDTO, logger);
        if (run.status() == ExperimentDAO.Status.success) {
            keepRun(run, experimentExecutionDTO.analysis(), started, user, logger);
        }
        return run;
    }

    private void keepRun(ExperimentDTO run, AnalysisRequestDTO analysis, Date started, UserDTO user,
            Logger logger) {
        ExperimentRunDAO runDAO = new ExperimentRunDAO();
        runDAO.setUuid(run.uuid());
        runDAO.setCreatedByUsername(user.username());
        runDAO.setAnalysis(convertObjectToJsonString(analysis));
        runDAO.setAlgorithmId(analysis.algorithm().name());
        runDAO.setResult(convertObjectToJsonString(run.result()));
        runDAO.setCreated(started);
        runDAO.setFinished(new Date());
        runDAO.setMipVersion(mipVersion);

        // Purging is housekeeping; a failure here must not stop this run from being kept.
        try {
            experimentRunRepository.deleteCreatedBefore(runDraftCutoff());
        } catch (Exception e) {
            logger.warn("Failed to purge expired runs: " + e.getMessage());
        }

        // The result is still returned when it cannot be kept; saving it later then reports it as missing.
        try {
            experimentRunRepository.save(runDAO);
        } catch (Exception e) {
            logger.error("Failed to keep the run in the database: " + e.getMessage());
        }
    }

    /**
     * Persists a run kept by {@link #runExperiment} as an experiment of the active user. The stored
     * analysis and result are the ones the run produced; nothing is sent to Exaflow.
     */
    public ExperimentDTO saveExperimentRun(UserDTO user, String runId, String name, Logger logger) {
        if (name == null || name.isBlank()) {
            throw new BadRequestException("An experiment name is required.");
        }
        if (runId == null || runId.isBlank()) {
            throw new BadRequestException("A runId is required.");
        }

        // Dataset access was validated when the run executed; the kept run is owner-only, so it is not checked again.
        ExperimentRunDAO run = loadKeptRun(runId, user, logger);

        ExperimentDAO experimentDAO = experimentRepository.createExperimentFromRun(run, name.trim(), user, logger);
        return new ExperimentDTO(experimentDAO, false);
    }

    private ExperimentRunDAO loadKeptRun(String runId, UserDTO user, Logger logger) {
        // Another user's run reads as missing, so run ids cannot be probed.
        return experimentRunRepository.findById(ExperimentRepository.parseUuid(runId, logger))
                .filter(run -> run.getCreatedByUsername().equals(user.username()))
                .filter(run -> !run.getCreated().before(runDraftCutoff()))
                .orElseThrow(() -> {
                    logger.warn("Run to save was not found or has expired. Id: " + runId);
                    return new ExperimentNotFoundException(
                            "This run is no longer available to save. Run the experiment again.");
                });
    }

    private Date runDraftCutoff() {
        return new Date(System.currentTimeMillis() - runDraftTtl.toMillis());
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
