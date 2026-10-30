package com.identityos.onboarding_and_identity_service.integration;
import org.springframework.core.annotation.Order;
import org.springframework.dao.*;
import org.springframework.http.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;
@RestControllerAdvice(basePackageClasses=IntegrationController.class)
@Order(-10)
public class IntegrationExceptionHandler {
  @ExceptionHandler(ResponseStatusException.class) ResponseEntity<?> domain(ResponseStatusException e) {
    return ResponseEntity.status(e.getStatusCode()).body(ProblemDetail.forStatusAndDetail(e.getStatusCode(),e.getReason()==null?"Request failed":e.getReason()));
  }
  @ExceptionHandler({MethodArgumentNotValidException.class,org.springframework.http.converter.HttpMessageNotReadableException.class})
  ResponseEntity<?> invalid(Exception e) { return problem(HttpStatus.BAD_REQUEST,"Invalid request"); }
  @ExceptionHandler(DataIntegrityViolationException.class) ResponseEntity<?> conflict(Exception e) { return problem(HttpStatus.CONFLICT,"Identity or configuration conflict"); }
  @ExceptionHandler({RestClientException.class,DataAccessResourceFailureException.class}) ResponseEntity<?> unavailable(Exception e) { return problem(HttpStatus.SERVICE_UNAVAILABLE,"Integration dependency unavailable"); }
  private ResponseEntity<?> problem(HttpStatus status,String detail) { return ResponseEntity.status(status).body(ProblemDetail.forStatusAndDetail(status,detail)); }
}
