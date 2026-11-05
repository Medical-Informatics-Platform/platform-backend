package hbp.mip.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;

import java.lang.reflect.Type;

public class JsonConverters {
    // LONG_OR_DOUBLE keeps JSON integers integral in Object-typed values (Gson defaults to double).
    private static final Gson gson = new GsonBuilder().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();
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
