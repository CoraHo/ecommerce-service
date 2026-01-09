package com.coraho.ecommerceservice.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ValidationError {
    private String field;
    private String message;
    private Object rejectedValue;

    public ValidationError(String field, String message) {
        this.field = field;
        this.message = message;
    }
}
