package hbp.mip.utils;

import hbp.mip.datamodel.DataModelDTO;
import hbp.mip.datamodel.DatasetLabels;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.UnauthorizedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component
public class ClaimUtils {

    @Value("${authentication.all_datasets_allowed_claim}")
    private String allDatasetsAllowedClaim;

    @Value("${authentication.all_analyses_allowed_claim}")
    private String allAnalysesAllowedClaim;

    @Value("${authentication.dataset_claim_prefix}")
    private String datasetClaimPrefix;

    /**
     * The role that grants a dataset: the prefix and the dataset LABEL. Codes are numeric and carry no
     * meaning for administrators, so roles name the readable label (for example research_dataset_edsd).
     */
    private String getDatasetClaim(String datasetLabel) {
        return datasetClaimPrefix + datasetLabel;
    }

    /** Roles compare in lowercase with whitespace, '+', '[' and ']' removed; a label is held to the same rule. */
    private static String normalizeRole(String role) {
        return role.toLowerCase(Locale.ROOT).replaceAll("[\\s+\\]\\[]", "");
    }

    private static boolean hasRoleAccess(List<String> authorities, String role, Logger logger) {
        String wanted = normalizeRole(role);
        boolean granted = authorities.stream().anyMatch(authority -> normalizeRole(authority).equals(wanted));
        logger.debug("Role " + wanted + (granted ? " granted." : " not granted."));
        return granted;
    }

    private static ArrayList<String> getAuthorityRoles(Authentication authentication) {
        return (ArrayList<String>) authentication.getAuthorities().stream()
                .map(Object::toString)
                .collect(Collectors.toList());
    }

    /**
     * True when the user holds the role of every label the dataset reference stands for. A reference
     * that resolves to no label is never allowed: nothing says which role would grant it.
     */
    private boolean mayUseDataset(List<String> authorities, String dataModel, String dataset, DatasetLabels labels,
                                  Logger logger) {
        Set<String> datasetLabels = labels.labelsFor(dataModel, dataset);
        if (datasetLabels.isEmpty()) {
            logger.warn("Dataset " + dataset + " is not known in data model " + dataModel + ": access denied.");
            return false;
        }
        return datasetLabels.stream().allMatch(label -> hasRoleAccess(authorities, getDatasetClaim(label), logger));
    }

    /**
     * Refuses the request unless the user may use every dataset of the data model. Datasets are the
     * codes sent by the UI, or the legacy text codes of analysiss saved before codes were numeric;
     * the labels are only fetched when the all-datasets role does not already cover them.
     */
    public void validateAccessRightsOnDatasets(Authentication authentication, String dataModel,
                                               List<String> analysisDatasets, Supplier<DatasetLabels> labels,
                                               Logger logger) {
        if (analysisDatasets == null || analysisDatasets.isEmpty()) {
            String errorMessage = "At least one dataset must be provided.";
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }

        ArrayList<String> authorities = getAuthorityRoles(authentication);

        if (!hasRoleAccess(authorities, allDatasetsAllowedClaim, logger)) {
            DatasetLabels datasetLabels = labels.get();
            for (String dataset : analysisDatasets) {
                if (!mayUseDataset(authorities, dataModel, dataset, datasetLabels, logger)) {
                    logger.warn("You are not allowed to use dataset: " + dataset);
                    throw new UnauthorizedException("You are not authorized to use these datasets.");
                }
            }
            logger.debug("User is authorized to use the datasets: " + analysisDatasets);
        }
    }

    /** True when the user may use every one of the datasets. No datasets named: false, nothing proves access. */
    public boolean hasAccessRightsOnDatasets(Authentication authentication, String dataModel, List<String> datasets,
                                             Supplier<DatasetLabels> labels, Logger logger) {
        if (datasets == null || datasets.isEmpty()) {
            return false;
        }
        ArrayList<String> authorities = getAuthorityRoles(authentication);
        if (hasRoleAccess(authorities, allDatasetsAllowedClaim, logger)) {
            return true;
        }
        DatasetLabels datasetLabels = labels.get();
        return datasets.stream().allMatch(dataset -> mayUseDataset(authorities, dataModel, dataset, datasetLabels, logger));
    }

    /**
     * Per data model, the lowercase dataset references (codes and labels) the user may use; null when the
     * all-datasets role covers every dataset. Same rule as {@link #hasAccessRightsOnDatasets}, so a
     * listing and a single read agree.
     */
    public Map<String, List<String>> usableDatasets(Authentication authentication, Supplier<DatasetLabels> labels,
                                                    Logger logger) {
        ArrayList<String> authorities = getAuthorityRoles(authentication);
        if (hasRoleAccess(authorities, allDatasetsAllowedClaim, logger)) {
            return null;
        }
        DatasetLabels datasetLabels = labels.get();
        Map<String, List<String>> usable = new HashMap<>();
        for (String dataModel : datasetLabels.dataModels()) {
            List<String> references = datasetLabels.references(dataModel).stream()
                    .filter(reference -> mayUseDataset(authorities, dataModel, reference, datasetLabels, logger))
                    .sorted()
                    .toList();
            if (!references.isEmpty()) {
                usable.put(dataModel, references);
            }
        }
        return usable;
    }

    public boolean validateAccessRightsOnALLAnalyses(Authentication authentication, Logger logger) {
        ArrayList<String> authorities = getAuthorityRoles(authentication);
        return hasRoleAccess(authorities, allAnalysesAllowedClaim, logger);
    }

    public List<DataModelDTO> getAuthorizedDataModels(Logger logger, Authentication authentication,
                                                      List<DataModelDTO> allDataModels) {
        ArrayList<String> authorities = getAuthorityRoles(authentication);

        if (hasRoleAccess(authorities, allDatasetsAllowedClaim, logger)) {
            return allDataModels;
        }

        List<DataModelDTO> userDataModels = new ArrayList<>();
        for (DataModelDTO curDataModel : allDataModels) {
            List<DataModelDTO.EnumerationDTO> dataModelDatasets = curDataModel.datasets();
            if (dataModelDatasets == null || dataModelDatasets.isEmpty()) {
                continue;
            }

            List<DataModelDTO.EnumerationDTO> userDataModelDatasets = new ArrayList<>();
            Map<String, List<String>> filteredDatasetVariables = new HashMap<>();
            Map<String, List<String>> originalDatasetVariables = curDataModel.datasetsVariables();

            for (DataModelDTO.EnumerationDTO dataset : dataModelDatasets) {
                // The role names the dataset label; a dataset without one cannot be granted.
                if (dataset.label() == null || dataset.label().isBlank()
                        || !hasRoleAccess(authorities, getDatasetClaim(dataset.label()), logger)) {
                    continue;
                }

                userDataModelDatasets.add(dataset);
                // Unknown variables (null or []) are omitted, same rule as DataModelService.
                List<String> variables = originalDatasetVariables == null ? null : originalDatasetVariables.get(dataset.code());
                if (variables != null && !variables.isEmpty()) {
                    filteredDatasetVariables.put(dataset.code(), variables);
                }
            }

            if (userDataModelDatasets.isEmpty()) {
                continue;
            }

            List<DataModelDTO.EnumerationDTO> safeDatasets = Collections.unmodifiableList(new ArrayList<>(userDataModelDatasets));
            Map<String, List<String>> userDatasetsVariables = filteredDatasetVariables.isEmpty()
                    ? Collections.emptyMap()
                    : Collections.unmodifiableMap(filteredDatasetVariables);

            DataModelDTO userDataModel = new DataModelDTO(
                    curDataModel.code(),
                    curDataModel.version(),
                    curDataModel.label(),
                    curDataModel.longitudinal(),
                    curDataModel.variables(),
                    curDataModel.groups(),
                    safeDatasets,
                    userDatasetsVariables
            );
            userDataModels.add(userDataModel);
        }
        return userDataModels;
    }
}
