package hbp.mip.analysis;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.algorithm.AnalysisExecutionService;
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
public class AnalysisService {

    private static final int MAX_PAGE_SIZE = 50;

    private final ActiveUserService activeUserService;
    private final ClaimUtils claimUtils;
    private final AnalysisRepository analysisRepository;
    private final AnalysisRunRepository analysisRunRepository;
    private final AnalysisExecutionService analysisExecutionService;
    private final boolean authenticationIsEnabled;
    private final String mipVersion;
    private final Duration runDraftTtl;

    public AnalysisService(
            ActiveUserService activeUserService,
            ClaimUtils claimUtils,
            AnalysisRepository analysisRepository,
            AnalysisRunRepository analysisRunRepository,
            AnalysisExecutionService analysisExecutionService,
            @Value("${authentication.enabled}") boolean authenticationIsEnabled,
            @Value("${mip.version}") String mipVersion,
            @Value("${experiments.run-draft-ttl}") Duration runDraftTtl) {
        this.activeUserService = activeUserService;
        this.claimUtils = claimUtils;
        this.analysisRepository = analysisRepository;
        this.analysisRunRepository = analysisRunRepository;
        this.analysisExecutionService = analysisExecutionService;
        this.authenticationIsEnabled = authenticationIsEnabled;
        this.mipVersion = mipVersion;
        this.runDraftTtl = runDraftTtl;
    }

    public AnalysesDTO getAnalyses(Authentication authentication, String name, String algorithm, Boolean shared,
            Boolean viewed, boolean includeShared, boolean mine, boolean notMine, int page, int size, String orderBy,
            Boolean descending,
            Logger logger) {
        validatePageSize(size);

        Specification<AnalysisDAO> spec = buildAnalysisSpecification(authentication, name, algorithm, shared,
                viewed, includeShared, mine, notMine, orderBy, descending, logger);
        Pageable pageable = PageRequest.of(page, size);
        Page<AnalysisDAO> analysesPage = analysisRepository.findAll(spec, pageable);

        if (analysesPage.isEmpty()) {
            throw new NoContent("No analysis found with the filters provided.");
        }

        return createAnalysesDTO(analysesPage);
    }

    private void validatePageSize(int size) {
        if (size > MAX_PAGE_SIZE) {
            throw new BadRequestException("Invalid size input, max size is " + MAX_PAGE_SIZE);
        }
    }

    private Specification<AnalysisDAO> buildAnalysisSpecification(Authentication authentication, String name,
            String algorithm, Boolean shared, Boolean viewed, boolean includeShared, boolean mine, boolean notMine,
            String orderBy,
            Boolean descending, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        boolean hasAccessRights = !authenticationIsEnabled
                || claimUtils.validateAccessRightsOnALLAnalyses(authentication, logger);

        Specification<AnalysisDAO> spec;

        if (mine) {
            spec = Specification.where(new AnalysisSpecifications.MyAnalysis(user.username()));
        } else if (notMine) {
            spec = Specification.where(new AnalysisSpecifications.NotMyAnalysis(user.username()))
                    .and(sharedAndReadable(authentication, true, hasAccessRights, logger));
        } else if (hasAccessRights) {
            spec = (root, query, criteriaBuilder) -> criteriaBuilder.conjunction();
        } else {
            spec = Specification.where(new AnalysisSpecifications.MyAnalysis(user.username()))
                    .or(sharedAndReadable(authentication, includeShared, hasAccessRights, logger));
        }

        return spec
                .and(new AnalysisSpecifications.AnalysisWithName(name))
                .and(new AnalysisSpecifications.AnalysisWithAlgorithm(algorithm))
                .and(new AnalysisSpecifications.AnalysisWithShared(shared))
                .and(new AnalysisSpecifications.AnalysisWithViewed(viewed))
                .and(new AnalysisSpecifications.AnalysisOrderBy(orderBy, descending));
    }

    // canRead's rule for lists, in the query: filtering afterwards would let totals and filters reveal hidden analyses.
    private Specification<AnalysisDAO> sharedAndReadable(Authentication authentication, boolean shared,
            boolean hasAccessRights, Logger logger) {
        Specification<AnalysisDAO> spec = new AnalysisSpecifications.SharedAnalysis(shared);
        List<String> datasets = hasAccessRights ? null : claimUtils.usableDatasets(authentication, logger);
        return datasets == null
                ? spec
                : spec.and(new AnalysisSpecifications.DatasetsReadable(convertObjectToJsonString(datasets)));
    }

    private AnalysesDTO createAnalysesDTO(Page<AnalysisDAO> pageAnalyses) {
        List<AnalysisDTO> analyses = pageAnalyses.map(analysisDAO -> new AnalysisDTO(analysisDAO, false))
                .getContent();
        return new AnalysesDTO(analyses, pageAnalyses.getNumber(), pageAnalyses.getTotalPages(),
                pageAnalyses.getTotalElements());
    }

    public AnalysisDTO getAnalysis(Authentication authentication, String uuid, Logger logger) {
        AnalysisDAO analysisDAO = assertAnalysisAccessible(authentication, uuid, logger);

        return new AnalysisDTO(analysisDAO, true);
    }

    /**
     * Loads an analysis and refuses it when the active user may not read it, returning the entity so
     * other features can reference a run they are allowed to see.
     *
     * Feature code that only needs to know "is this run usable by this user" should call this instead
     * of reopening the access rules, which live in one place on purpose.
     */
    public AnalysisDAO assertAnalysisAccessible(Authentication authentication, String uuid, Logger logger) {
        AnalysisDAO analysisDAO = analysisRepository.loadAnalysis(uuid, logger);
        validateAnalysisAccess(authentication, analysisDAO, uuid, logger);

        return analysisDAO;
    }

    private void validateAnalysisAccess(Authentication authentication, AnalysisDAO analysisDAO, String uuid,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);

        if (!canRead(authentication, user, analysisDAO, logger)) {
            logger.warn("User tried to access an unauthorized analysis with id:" + uuid);
            throw new UnauthorizedException("You don't have access to that analysis.");
        }
    }

    /** Sharing an analysis does not open its data: others also need the datasets it ran on. */
    private boolean canRead(Authentication authentication, UserDTO user, AnalysisDAO analysisDAO, Logger logger) {
        if (!authenticationIsEnabled
                || analysisDAO.getCreatedBy().getUsername().equals(user.username())
                || claimUtils.validateAccessRightsOnALLAnalyses(authentication, logger)) {
            return true;
        }
        return analysisDAO.isShared()
                && claimUtils.hasAccessRightsOnDatasets(authentication, datasetsOf(analysisDAO), logger);
    }

    private static List<String> datasetsOf(AnalysisDAO analysisDAO) {
        AnalysisRequestDTO analysis = AnalysisRequestDTO.fromStored(analysisDAO.getAnalysisRequest());
        return analysis != null && analysis.inputdata() != null ? analysis.inputdata().allDatasets() : null;
    }

    private void validateDatasetAccess(Authentication authentication, AnalysisRequestDTO analysis, Logger logger) {
        if (authenticationIsEnabled) {
            claimUtils.validateAccessRightsOnDatasets(authentication, analysis.inputdata().allDatasets(), logger);
        }
    }

    /** Runs an analysis and returns its result without storing anything. */
    public AnalysisDTO previewAnalysis(Authentication authentication,
            AnalysisExecutionDTO analysisExecutionDTO, Logger logger) {
        AnalysisExecutionService.requireRunnable(analysisExecutionDTO.analysisRequest(), logger);
        analysisParametersLogging(analysisExecutionDTO, logger);

        validateDatasetAccess(authentication, analysisExecutionDTO.analysisRequest(), logger);
        UUID uuid = UUID.randomUUID();
        AnalysisExecutionService.AnalysisResultDTO analysisResult = analysisExecutionService.runAnalysis(
                uuid,
                analysisExecutionDTO.analysisRequest(),
                logger);

        return new AnalysisDTO(uuid, analysisExecutionDTO.name(), null, null, null, null, null, null,
                analysisResult.body(),
                analysisResult.code() >= 400 ? AnalysisDAO.Status.error : AnalysisDAO.Status.success,
                analysisExecutionDTO.analysisRequest(),
                mipVersion);
    }

    /**
     * Runs an analysis like {@link #previewAnalysis} and, when it succeeds, keeps the result so
     * {@link #saveAnalysisRun} can persist it later without executing the analysis again. The
     * returned uuid is the run id to save.
     */
    public AnalysisDTO runAnalysis(Authentication authentication, UserDTO user,
            AnalysisExecutionDTO analysisExecutionDTO, Logger logger) {
        Date started = new Date();
        AnalysisDTO run = previewAnalysis(authentication, analysisExecutionDTO, logger);
        if (run.status() == AnalysisDAO.Status.success) {
            keepRun(run, analysisExecutionDTO.analysisRequest(), started, user, logger);
        }
        return run;
    }

    private void keepRun(AnalysisDTO run, AnalysisRequestDTO analysis, Date started, UserDTO user,
            Logger logger) {
        AnalysisRunDAO runDAO = new AnalysisRunDAO();
        runDAO.setUuid(run.uuid());
        runDAO.setCreatedByUsername(user.username());
        runDAO.setAnalysisRequest(convertObjectToJsonString(analysis));
        runDAO.setAlgorithmId(analysis.algorithm().name());
        runDAO.setResult(convertObjectToJsonString(run.result()));
        runDAO.setCreated(started);
        runDAO.setFinished(new Date());
        runDAO.setMipVersion(mipVersion);

        // Purging is housekeeping; a failure here must not stop this run from being kept.
        try {
            analysisRunRepository.deleteCreatedBefore(runDraftCutoff());
        } catch (Exception e) {
            logger.warn("Failed to purge expired runs: " + e.getMessage());
        }

        // The result is still returned when it cannot be kept; saving it later then reports it as missing.
        try {
            analysisRunRepository.save(runDAO);
        } catch (Exception e) {
            logger.error("Failed to keep the run in the database: " + e.getMessage());
        }
    }

    /**
     * Persists a run kept by {@link #runAnalysis} as an analysis of the active user. The stored
     * analysis and result are the ones the run produced; nothing is sent to Exaflow.
     */
    public AnalysisDTO saveAnalysisRun(UserDTO user, String runId, String name, Logger logger) {
        if (name == null || name.isBlank()) {
            throw new BadRequestException("An analysis name is required.");
        }
        if (runId == null || runId.isBlank()) {
            throw new BadRequestException("A runId is required.");
        }

        // Dataset access was validated when the run executed; the kept run is owner-only, so it is not checked again.
        AnalysisRunDAO run = loadKeptRun(runId, user, logger);

        AnalysisDAO analysisDAO = analysisRepository.createAnalysisFromRun(run, name.trim(), user, logger);
        return new AnalysisDTO(analysisDAO, false);
    }

    private AnalysisRunDAO loadKeptRun(String runId, UserDTO user, Logger logger) {
        // Another user's run reads as missing, so run ids cannot be probed.
        return analysisRunRepository.findById(AnalysisRepository.parseUuid(runId, logger))
                .filter(run -> run.getCreatedByUsername().equals(user.username()))
                .filter(run -> !run.getCreated().before(runDraftCutoff()))
                .orElseThrow(() -> {
                    logger.warn("Run to save was not found or has expired. Id: " + runId);
                    return new AnalysisNotFoundException(
                            "This run is no longer available to save. Run the analysis again.");
                });
    }

    private Date runDraftCutoff() {
        return new Date(System.currentTimeMillis() - runDraftTtl.toMillis());
    }

    public AnalysisDTO updateAnalysis(UserDTO user, String uuid, AnalysisDTO analysis, Logger logger) {
        AnalysisDAO analysisDAO = analysisRepository.loadAnalysis(uuid, logger);

        verifyNonEditableFieldsAreNotBeingModified(analysis, logger);
        checkUpdateAuthorization(user, analysisDAO, uuid, logger);

        updateModifiableFields(analysis, analysisDAO);
        analysisDAO.setUpdated(new Date());

        try {
            analysisRepository.save(analysisDAO);
        } catch (Exception e) {
            logger.error("Failed to save to the database: " + e.getMessage());
            throw new InternalServerError(e.getMessage());
        }

        return new AnalysisDTO(analysisDAO, true);
    }

    private void checkUpdateAuthorization(UserDTO user, AnalysisDAO analysisDAO, String uuid, Logger logger) {
        if (!analysisDAO.getCreatedBy().getUsername().equals(user.username())) {
            logger.warn("User tried to modify an unauthorized analysis with uuid: " + uuid);
            throw new UnauthorizedException("You don't have access to modify the analysis.");
        }
    }

    private void updateModifiableFields(AnalysisDTO analysis, AnalysisDAO analysisDAO) {
        if (analysis.name() != null && !analysis.name().isEmpty()) {
            analysisDAO.setName(analysis.name());
        }
        if (analysis.shared() != null) {
            analysisDAO.setShared(analysis.shared());
        }
        if (analysis.viewed() != null) {
            analysisDAO.setViewed(analysis.viewed());
        }
    }

    public void deleteAnalysis(UserDTO user, String uuid, Logger logger) {
        AnalysisDAO analysisDAO = analysisRepository.loadAnalysis(uuid, logger);

        checkDeleteAuthorization(user, analysisDAO, uuid, logger);

        try {
            analysisRepository.delete(analysisDAO);
        } catch (Exception e) {
            logger.info("Attempted to delete an analysis from the database but an error occurred: " + e.getMessage());
            throw new InternalServerError(e.getMessage());
        }
    }

    private void checkDeleteAuthorization(UserDTO user, AnalysisDAO analysisDAO, String uuid, Logger logger) {
        if (!analysisDAO.getCreatedBy().getUsername().equals(user.username())) {
            logger.warn("User " + user.username() + " tried to delete the analysis with uuid " + uuid
                    + " but was unauthorized.");
            throw new UnauthorizedException("You don't have access to delete the analysis.");
        }
    }

    private void verifyNonEditableFieldsAreNotBeingModified(AnalysisDTO analysisDTO, Logger logger) {
        throwIfNonNull(analysisDTO.uuid(), "uuid", logger);
        throwIfNonNull(analysisDTO.createdBy(), "createdBy", logger);
        throwIfNonNull(analysisDTO.created(), "created", logger);
        throwIfNonNull(analysisDTO.updated(), "updated", logger);
        throwIfNonNull(analysisDTO.finished(), "finished", logger);
        throwIfNonNull(analysisDTO.result(), "result", logger);
        throwIfNonNull(analysisDTO.status(), "status", logger);
        throwIfNonNull(analysisDTO.analysisRequest(), "analysisRequest", logger);
    }

    private void throwIfNonNull(Object field, String nonEditableField, Logger logger) {
        if (field != null) {
            String errorMessage = "Tried to edit non-editable field: " + nonEditableField;
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
    }

    private void analysisParametersLogging(AnalysisExecutionDTO analysisExecutionDTO, Logger logger) {
        AnalysisRequestDTO analysis = analysisExecutionDTO.analysisRequest();
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
