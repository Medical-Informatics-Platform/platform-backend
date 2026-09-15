package hbp.mip.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import java.lang.reflect.Type;

/**
 * Serialization uses Jackson (Exaflow request bodies and persisted JSON); deserialization uses Gson
 * for the TypeToken-based Exaflow specifications. Keep annotations in sync for both engines: a field
 * renamed for Gson needs a Jackson counterpart (see ParameterSpecificationDTO).
 */
public class JsonConverters {
    private static final Gson gson = new Gson();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static String convertObjectToJsonString(Object object) {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            return e.getMessage();
        }
    }

    public static  <T> T convertJsonStringToObject(String jsonString, Type typeOfT)  {
        if(jsonString == null || jsonString.isEmpty())
            return null;
        return gson.fromJson(jsonString, typeOfT);
    }
}
