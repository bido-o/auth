package com.bido.auth.dto;

public record VerifyOtpRequest(String email, String otpCode) {}
