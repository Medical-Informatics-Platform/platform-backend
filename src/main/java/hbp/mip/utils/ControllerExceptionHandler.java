package hbp.mip.utils;

import hbp.mip.utils.Exceptions.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Arrays;
import java.util.Date;

@ControllerAdvice
public class ControllerExceptionHandler extends ResponseEntityExceptionHandler {

    public record ErrorMessage (int statusCode, Date timestamp, String message, String description) {}

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<Object> handleNotFoundException(NotFoundException ex, WebRequest request) {
        return respond(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<Object> handleConflictException(ConflictException ex, WebRequest request) {
        return respond(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<Object> handleBadRequestException(BadRequestException ex, WebRequest request) {
        return respond(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<Object> handleUnauthorizedException(UnauthorizedException ex, WebRequest request) {
        return respond(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    @ExceptionHandler(NoAuthorizedPathologiesException.class)
    public ResponseEntity<Object> handleNoAuthorizedPathologiesException(
            NoAuthorizedPathologiesException ex,
            WebRequest request
    ) {
        return respond(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    @ExceptionHandler(NoPathologiesAvailableException.class)
    public ResponseEntity<Object> handleNoPathologiesAvailableException(
            NoPathologiesAvailableException ex,
            WebRequest request
    ) {
        return respond(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    @ExceptionHandler(NoContent.class)
    public ResponseEntity<Void> handleNoContent(NoContent nc, WebRequest request) {
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @ExceptionHandler({InternalServerError.class, Exception.class})
    public ResponseEntity<Object> globalExceptionHandler(Exception ex, WebRequest request) {
        logger.error("An unexpected exception occurred: " + ex.getClass() +
                " Message: " + ex.getMessage() +
                " Stacktrace: " + Arrays.toString(ex.getStackTrace())
        );
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage(), request);
    }

    private static ResponseEntity<Object> respond(HttpStatus status, String message, WebRequest request) {
        ErrorMessage body = new ErrorMessage(
                status.value(),
                new Date(),
                message,
                request.getDescription(false));

        return new ResponseEntity<>(body, status);
    }
}
