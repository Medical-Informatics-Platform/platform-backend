package hbp.mip.utils;

import org.slf4j.LoggerFactory;

public class Logger {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Logger.class);
    private final String username;
    private final String endpoint;

    public Logger(String username, String endpoint) {
        this.username = username;
        this.endpoint = endpoint;
    }

    public void error(String message) {
        logger.error("User -> {} , Endpoint -> {} , Info -> {}", username, endpoint, message);
    }

    public void warn(String message) {
        logger.warn("User -> {} , Endpoint -> {} , Info -> {}", username, endpoint, message);
    }

    public void info(String message) {
        logger.info("User -> {} , Endpoint -> {} , Info -> {}", username, endpoint, message);
    }

    public void debug(String message) {
        logger.debug("User -> {} , Endpoint -> {} , Info -> {}", username, endpoint, message);
    }
}
