package com.bido.auth.controller;

import com.bido.auth.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import com.bido.auth.utils.ErrorMessages;

@Tag(name = "Authentication", description = "Endpoint-uri pentru generarea și validarea tokenurilor")
public interface AuthApiDocs {

    @Operation(summary = "Cere cod OTP", description = "Trimite un cod de 6 cifre pe email. Creează contul dacă nu există.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Codul a fost generat și trimis cu succes."),
            @ApiResponse(responseCode = "400", description = "Erori de validare a rolului", content = @Content(
                    mediaType = "application/json",
                    examples = {
                            @ExampleObject(name = "Rol Administrator (Invalid)", value = "{\n  \"status\": 400,\n  \"error\": \"Bad Request\",\n  \"message\": \"" + ErrorMessages.ROLE_ADMIN_INVALID + "\",\n  \"path\": \"/api/auth/request-otp\"\n}"),
                            @ExampleObject(name = "Rol Lipsă", value = "{\n  \"status\": 400,\n  \"error\": \"Bad Request\",\n  \"message\": \"" + ErrorMessages.ROLE_MISSING + "\",\n  \"path\": \"/api/auth/request-otp\"\n}")
                    }
            )),
            @ApiResponse(responseCode = "403", description = "Eroare de acces", content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(name = "Cont Suspendat", value = "{\n  \"status\": 403,\n  \"error\": \"Forbidden\",\n  \"message\": \"" + ErrorMessages.ACCOUNT_SUSPENDED + "\",\n  \"path\": \"/api/auth/request-otp\"\n}")
            )),
            @ApiResponse(responseCode = "429", description = "Erori de limitare a traficului (Spam)", content = @Content(
                    mediaType = "application/json",
                    examples = {
                            @ExampleObject(name = "Prea multe coduri cerute", value = "{\n  \"status\": 429,\n  \"error\": \"Too Many Requests\",\n  \"message\": \"" + ErrorMessages.RATE_LIMIT_TOKENS + "\",\n  \"path\": \"/api/auth/request-otp\"\n}"),
                            @ExampleObject(name = "Cont blocat temporar", value = "{\n  \"status\": 429,\n  \"error\": \"Too Many Requests\",\n  \"message\": \"" + ErrorMessages.RATE_LIMIT_BLOCKED + "\",\n  \"path\": \"/api/auth/request-otp\"\n}")
                    }
            ))
    })
    ResponseEntity<Void> requestOtp(@RequestBody RequestOtpRequest request);

    @Operation(summary = "Verifică codul OTP", description = "Validează codul OTP și returnează perechea de tokenuri JWT.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Autentificare cu succes. Returnează Access Token și Refresh Token."),
            @ApiResponse(responseCode = "401", description = "Erori de validare OTP", content = @Content(
                    mediaType = "application/json",
                    examples = {
                            @ExampleObject(name = "Cod Expirat", value = "{\n  \"status\": 401,\n  \"error\": \"Unauthorized\",\n  \"message\": \"" + ErrorMessages.OTP_EXPIRED + "\",\n  \"path\": \"/api/auth/verify-otp\"\n}"),
                            @ExampleObject(name = "Cod Necerut", value = "{\n  \"status\": 401,\n  \"error\": \"Unauthorized\",\n  \"message\": \"" + ErrorMessages.OTP_NOT_REQUESTED + "\",\n  \"path\": \"/api/auth/verify-otp\"\n}"),
                            @ExampleObject(name = "Cod Incorect", value = "{\n  \"status\": 401,\n  \"error\": \"Unauthorized\",\n  \"message\": \"" + ErrorMessages.OTP_INCORRECT + "\",\n  \"path\": \"/api/auth/verify-otp\"\n}"),
                            @ExampleObject(name = "Limită Depășită", value = "{\n  \"status\": 401,\n  \"error\": \"Unauthorized\",\n  \"message\": \"" + ErrorMessages.OTP_MAX_ATTEMPTS + "\",\n  \"path\": \"/api/auth/verify-otp\"\n}")
                    }
            ))
    })
    ResponseEntity<AuthResponse> verifyOtp(@RequestBody VerifyOtpRequest request);

    @Operation(summary = "Reîmprospătare Token", description = "Folosește Refresh Token-ul valid pentru a genera un nou Access Token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token reînnoit cu succes. Returnează o nouă pereche de tokenuri."),
            @ApiResponse(responseCode = "401", description = "Erori de validare Refresh Token", content = @Content(
                    mediaType = "application/json",
                    examples = {
                            @ExampleObject(name = "Token Invalid", value = "{\n  \"status\": 401,\n  \"error\": \"Unauthorized\",\n  \"message\": \"" + ErrorMessages.TOKEN_REFRESH_INVALID + "\",\n  \"path\": \"/api/auth/refresh-token\"\n}"),
                            @ExampleObject(name = "Token Expirat", value = "{\n  \"status\": 401,\n  \"error\": \"Unauthorized\",\n  \"message\": \"" + ErrorMessages.TOKEN_EXPIRED + "\",\n  \"path\": \"/api/auth/refresh-token\"\n}")
                    }
            ))
    })
    ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request);
}