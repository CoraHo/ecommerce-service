package com.coraho.ecommerceservice.DTO;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Builder;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@Builder
public class ErrorResponse {
    private String timestamp;
    private int status;
    private String error;
    private String message;
    private String path;
    // provide detailed information about what went wrong during input validation
    private List<ValidationError> validationErrors;
    private String traceId; // For distributed tracing

}
