package com.identityos.onboarding_and_identity_service.integration;
import com.identityos.onboarding_and_identity_service.service.HostedIdentityVerificationService;
import com.identityos.onboarding_and_identity_service.client.trust.TrustSignalClient;
import com.identityos.onboarding_and_identity_service.dto.*;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.SimpleMailMessage;
import org.mockito.ArgumentCaptor;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class DevelopmentVerificationCompatibilityTests {
  @Test void existingDummyMobileOtpIsUnchanged() {
    var mail=mock(JavaMailSender.class);var service=new HostedIdentityVerificationService(mail,mock(TrustSignalClient.class),"no-reply@identity-os.local");
    var sent=service.requestOtp(new HostedIdentityOtpRequest("app_test","mobile","phone","9999999999"));
    var verified=service.verifyOtp(new HostedIdentityOtpVerifyRequest("app_test","mobile","9999999999","123456",sent.verificationId()));
    assertTrue(verified.verified());verifyNoInteractions(mail);
  }
  @Test void existingEmailSenderStillReceivesTheVerificationMessage() {
    var mail=mock(JavaMailSender.class);var service=new HostedIdentityVerificationService(mail,mock(TrustSignalClient.class),"no-reply@identity-os.local");
    service.requestOtp(new HostedIdentityOtpRequest("app_test","email","email","alice@example.test"));
    var message=ArgumentCaptor.forClass(SimpleMailMessage.class);verify(mail).send(message.capture());
    assertEquals("no-reply@identity-os.local",message.getValue().getFrom());
    assertArrayEquals(new String[]{"alice@example.test"},message.getValue().getTo());
    assertTrue(message.getValue().getText().matches("(?s).*\\d{6}.*"));
  }
}
