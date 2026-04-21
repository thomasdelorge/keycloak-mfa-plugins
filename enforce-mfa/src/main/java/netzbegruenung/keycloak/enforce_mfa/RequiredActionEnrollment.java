package netzbegruenung.keycloak.enforce_mfa;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Determines whether a required action's enrollment can be considered satisfied (credential present).
 */
public final class RequiredActionEnrollment {

	private static final Map<String, String> CREDENTIAL_TYPE_BY_REQUIRED_ACTION_ID = Map.of(
		"CONFIGURE_TOTP", "otp",
		"webauthn-register", "webauthn",
		"webauthn-register-passwordless", "webauthn-passwordless",
		"email-authenticator-setup", "email-authenticator"
	);

	private RequiredActionEnrollment() {
	}

	public static boolean isSatisfied(KeycloakSession session, RealmModel realm, UserModel user, String requiredActionProviderId) {
		String cred = CREDENTIAL_TYPE_BY_REQUIRED_ACTION_ID.get(requiredActionProviderId);
		if (cred != null) {
			return user.credentialManager().isConfiguredFor(cred);
		}
		return user.getRequiredActionsStream().noneMatch(requiredActionProviderId::equals);
	}
}
