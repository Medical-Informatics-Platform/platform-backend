package hbp.mip.datamodel;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The dataset codes of each data model with their labels, from the {@code dataset} CDE enumerations.
 * Dataset access is granted per label, so every access check starts by resolving what a stored or
 * requested dataset reference means here; an empty answer means the reference is unknown and is denied.
 */
public record DatasetLabels(Map<String, Map<String, String>> labelsByCodeByDataModel) {

    public static final DatasetLabels NONE = new DatasetLabels(Map.of());

    public DatasetLabels {
        labelsByCodeByDataModel = labelsByCodeByDataModel == null ? Map.of() : Map.copyOf(labelsByCodeByDataModel);
    }

    /**
     * The labels a dataset reference stands for in a data model; empty when it cannot be resolved.
     * A reference is a dataset code (compared case-insensitively). When no code matches, it may be a
     * legacy text code kept by an analysis saved before codes became numeric: it then has to equal
     * a dataset label, ignoring case. Several labels come back only when the reference is ambiguous,
     * and callers then need the role of every one of them.
     */
    public Set<String> labelsFor(String dataModel, String reference) {
        Map<String, String> labelsByCode = dataModel == null ? null : labelsByCodeByDataModel.get(dataModel);
        if (labelsByCode == null || reference == null || reference.isBlank()) {
            return Set.of();
        }
        String wanted = reference.toLowerCase(Locale.ROOT);

        Set<String> byCode = new HashSet<>();
        Set<String> byLabel = new HashSet<>();
        labelsByCode.forEach((code, label) -> {
            if (label == null || label.isBlank()) {
                return;
            }
            if (code != null && code.toLowerCase(Locale.ROOT).equals(wanted)) {
                byCode.add(label);
            }
            if (label.toLowerCase(Locale.ROOT).equals(wanted)) {
                byLabel.add(label);
            }
        });
        return Collections.unmodifiableSet(byCode.isEmpty() ? byLabel : byCode);
    }

    public Set<String> dataModels() {
        return labelsByCodeByDataModel.keySet();
    }

    /** Every lowercase code and label of the data model: the references that can resolve in it. */
    public Set<String> references(String dataModel) {
        Set<String> references = new HashSet<>();
        labelsByCodeByDataModel.getOrDefault(dataModel, Map.of()).forEach((code, label) -> {
            if (code != null) {
                references.add(code.toLowerCase(Locale.ROOT));
            }
            if (label != null && !label.isBlank()) {
                references.add(label.toLowerCase(Locale.ROOT));
            }
        });
        return references;
    }

    static DatasetLabels fromEnumerations(Map<String, Map<String, String>> enumerationsByDataModel) {
        Map<String, Map<String, String>> result = new LinkedHashMap<>();
        enumerationsByDataModel.forEach((dataModel, enumerations) -> {
            if (dataModel != null && enumerations != null) {
                result.put(dataModel, enumerations);
            }
        });
        return new DatasetLabels(result);
    }
}
