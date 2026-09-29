package hbp.mip.algorithm;

import com.google.gson.reflect.TypeToken;
import hbp.mip.utils.Exceptions.InternalServerError;
import hbp.mip.utils.HTTPUtil;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.lang.reflect.Type;
import java.util.List;

@Service
public class SpecificationsService {

    private static final Type PREPROCESSING_SPECIFICATIONS_TYPE =
            new TypeToken<List<PreprocessingStepSpecificationDTO>>() {
            }.getType();
    private static final Type ALGORITHM_SPECIFICATIONS_TYPE = new TypeToken<List<AlgorithmSpecificationDTO>>() {
    }.getType();

    @Value("${services.exaflow.inputdataSpecUrl}")
    private String inputdataSpecUrl;

    @Value("${services.exaflow.preprocessingSpecUrl}")
    private String preprocessingSpecUrl;

    @Value("${services.exaflow.algorithmsSpecUrl}")
    private String algorithmsSpecUrl;

    public AnalysisInputDataSpecificationDTO getInputdataSpecification(Logger logger) {
        return fetch(inputdataSpecUrl, AnalysisInputDataSpecificationDTO.class, "inputdata specification", logger);
    }

    public List<PreprocessingStepSpecificationDTO> getPreprocessingSpecifications(Logger logger) {
        return fetch(preprocessingSpecUrl, PREPROCESSING_SPECIFICATIONS_TYPE, "preprocessing specifications", logger);
    }

    public List<AlgorithmSpecificationDTO> getAlgorithmSpecifications(Logger logger) {
        return fetch(algorithmsSpecUrl, ALGORITHM_SPECIFICATIONS_TYPE, "algorithm specifications", logger);
    }

    private <T> T fetch(String url, Type typeOfT, String what, Logger logger) {
        StringBuilder response = new StringBuilder();
        try {
            HTTPUtil.sendGet(url, response);
            T specification = JsonConverters.convertJsonStringToObject(response.toString(), typeOfT);
            if (specification == null || (specification instanceof List<?> list && list.isEmpty())) {
                throw new InternalServerError("Exaflow " + what + " response was empty.");
            }
            return specification;
        } catch (Exception e) {
            logger.error("Could not fetch exaflow " + what + ": " + e.getMessage());
            throw new InternalServerError("Could not fetch exaflow " + what + ".");
        }
    }
}
