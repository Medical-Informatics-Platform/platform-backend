package hbp.mip.datamodel;

import com.google.gson.reflect.TypeToken;
import hbp.mip.utils.Exceptions.InternalServerError;
import hbp.mip.utils.HTTPUtil;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.lang.reflect.Type;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Dataset codes and labels of every data model, read from Exaflow's CDE metadata and kept for a short
 * time. Access checks run per request and per listed experiment, and labels change rarely.
 */
@Service
public class DatasetLabelService {

    private static final Type CDES_METADATA_TYPE =
            new TypeToken<Map<String, Map<String, DataModelService.CDEMetadata>>>() {
            }.getType();

    private final String apiToken;
    private final String cdesMetadataUrl;
    private final Duration ttl;

    private DatasetLabels cached = DatasetLabels.NONE;
    private long cachedAtNanos;
    private boolean hasCache;

    public DatasetLabelService(
            @Value("${services.exaflow.apiToken:}") String apiToken,
            @Value("${services.exaflow.cdesMetadataUrl}") String cdesMetadataUrl,
            @Value("${authentication.dataset_labels_cache_ttl:60s}") Duration ttl) {
        this.apiToken = apiToken;
        this.cdesMetadataUrl = cdesMetadataUrl;
        this.ttl = ttl;
    }

    /** @throws InternalServerError when the metadata cannot be fetched and there is no fresh copy. */
    public synchronized DatasetLabels get(Logger logger) {
        long now = System.nanoTime();
        if (hasCache && now - cachedAtNanos < ttl.toNanos()) {
            return cached;
        }
        try {
            DatasetLabels fetched = parse(fetchBody());
            cached = fetched;
            cachedAtNanos = now;
            hasCache = true;
            return fetched;
        } catch (Exception e) {
            hasCache = false;
            logger.error("Could not fetch the dataset labels from exaflow: " + e.getMessage());
            throw new InternalServerError("Could not fetch the dataset labels.");
        }
    }

    String fetchBody() throws java.io.IOException {
        StringBuilder response = new StringBuilder();
        HTTPUtil.sendGet(cdesMetadataUrl, apiToken, response);
        return response.toString();
    }

    static DatasetLabels parse(String json) {
        Map<String, Map<String, DataModelService.CDEMetadata>> cdes =
                JsonConverters.convertJsonStringToObject(json, CDES_METADATA_TYPE);
        Map<String, Map<String, String>> enumerations = new HashMap<>();
        if (cdes != null) {
            cdes.forEach((dataModel, cdesOfModel) -> {
                DataModelService.CDEMetadata dataset = cdesOfModel == null ? null : cdesOfModel.get("dataset");
                if (dataset != null && dataset.enumerations() != null) {
                    enumerations.put(dataModel, dataset.enumerations());
                }
            });
        }
        return DatasetLabels.fromEnumerations(enumerations);
    }
}
