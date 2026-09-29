package hbp.mip.algorithm;

import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.InternalServerError;
import hbp.mip.utils.HTTPUtil;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@Service
public class AnalysisService {

    private static final String GENERIC_ERROR_MESSAGE =
            "Something went wrong. Please inform the system administrator or try again later.";

    private final String analysisUrl;

    public AnalysisService(@Value("${services.exaflow.analysisUrl}") String analysisUrl) {
        this.analysisUrl = analysisUrl;
    }

    public AnalysisResultDTO runAnalysis(UUID requestId, AnalysisRequestDTO analysisRequest, Logger logger) {
        AnalysisRequestDTO requestWithId = AnalysisRequestDTO.withRequestId(requestId, analysisRequest);
        String requestBody = JsonConverters.convertObjectToJsonString(requestWithId);

        logger.debug("Exaflow analysis request, endpoint: " + analysisUrl);
        logger.debug("Exaflow analysis request, body: " + requestBody);

        int responseCode;
        var responseBody = new StringBuilder();
        try {
            responseCode = HTTPUtil.sendPost(analysisUrl, requestBody, responseBody);
        } catch (IOException e) {
            logger.error("Could not run the exaflow analysis: " + e.getMessage());
            throw new InternalServerError(e.getMessage());
        }

        Object result = convertResponseToAnalysisResult(logger, responseCode, responseBody);
        return new AnalysisResultDTO(responseCode, result);
    }

    public AnalysisResultDTO runAnalysis(AnalysisRequestDTO analysisRequest, Logger logger) {
        UUID requestId = analysisRequest.request_id() != null
                ? parseRequestId(analysisRequest.request_id(), logger)
                : UUID.randomUUID();
        return runAnalysis(requestId, analysisRequest, logger);
    }

    private static UUID parseRequestId(String requestId, Logger logger) {
        try {
            return UUID.fromString(requestId);
        } catch (IllegalArgumentException e) {
            String errorMessage = "Invalid request_id: must be a valid UUID.";
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
    }

    private static Object convertResponseToAnalysisResult(Logger logger, int code, StringBuilder responseBody) {
        return switch (code) {
            case 200 -> JsonConverters.convertJsonStringToObject(responseBody.toString(), Object.class);
            case 400, 460, 461, 462, 512, 513 -> convertExaflowResponseToAnalysisResult(responseBody.toString());
            case 500 -> convertExaflowResponseToAnalysisResult(GENERIC_ERROR_MESSAGE);
            default -> handleUnexpectedResponseCode(logger, code);
        };
    }

    private static Map<String, Object> convertExaflowResponseToAnalysisResult(String resultBody) {
        return Map.of("data", resultBody, "type", "text/plain+error");
    }

    private static Object handleUnexpectedResponseCode(Logger logger, int code) {
        String errorMessage = "Exaflow execution responded with an unexpected status code: " + code;
        logger.error(errorMessage);
        throw new InternalServerError(errorMessage);
    }

    public record AnalysisResultDTO(int code, Object body) {
    }
}
