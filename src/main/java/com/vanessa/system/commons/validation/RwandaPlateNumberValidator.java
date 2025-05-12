package com.vanessa.system.commons.validation;

import jakarta.validation.ConstraintValidator;

import jakarta.validation.ConstraintValidatorContext;

public class RwandaPlateNumberValidator implements ConstraintValidator<ValidPlateNumber, String> {

    private static final String PLATE_REGEX = "R[A-Z]{2}\\d{3}[A-Z]";

    @Override
    public boolean isValid(String plateNumber, ConstraintValidatorContext context) {
        if (plateNumber == null) {
            return false;
        }
        return plateNumber.matches(PLATE_REGEX);
    }
}
