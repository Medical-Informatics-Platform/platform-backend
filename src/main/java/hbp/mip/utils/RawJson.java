package hbp.mip.utils;

import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * JSON text that serializers write unchanged. Analysis results pass through as Exaflow sent them, so
 * integers stay integers and explicit nulls survive the application-wide {@code non_null} inclusion.
 */
public record RawJson(@JsonValue @JsonRawValue String json) {
}
