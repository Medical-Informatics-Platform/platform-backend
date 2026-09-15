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

    private String formatMessage(String message) {
        return "User -> " + username + " , Endpoint -> " + endpoint + " , Info -> " + message;
    }

    public void error(String message) {
        logger.error(formatMessage(message));
    }

    public void warn(String message) {
        logger.warn(formatMessage(message));
    }

    public void info(String message) {
        logger.info(formatMessage(message));
    }

    public void debug(String message) {
        logger.debug(formatMessage(message));
    }
}
