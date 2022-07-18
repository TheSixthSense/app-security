package com.app.security.core.exception;

import com.app.security.core.response.RestResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(JWTException.class)
    protected ResponseEntity<RestResponse<?>> handleJwtException(JWTException e) {
        log.error("handleJwtException throw Exception : {}", e);

        return ResponseEntity
                .status(e.getErrorCode().getStatus())
                .body(RestResponse
                        .withMetaSystemMessage(e.getMessage())
                        .build()
                );
    }
}
