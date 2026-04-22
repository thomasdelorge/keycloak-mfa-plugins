package netzbegruenung.keycloak.enforce_mfa;

import org.keycloak.models.Constants;

import java.util.List;
import java.util.Map;

/**
 * Shared config keys, admin multiselect option lists, and parsing of multivalued authenticator config (Keycloak delimiter).
 */
public final class EnforceMfaShared {

	private EnforceMfaShared() {
	}

	/** {@link ConditionalEnforceMfaAuthenticator} config: multiselect required actions shown on the screen. */
	public static final String CONFIG_OFFERED = "offeredRequiredActions";
	/** Same key as {@link EnforceMfaAuthenticator#CONFIG_OPTIONAL_NAME}. */
	public static final String CONFIG_OPTIONAL_NAME = "mfaSetupOptional";

	/** Credential type ids for {@link MfaCredentialConditionFactory} admin UI. */
	public static final List<String> CREDENTIAL_TYPE_OPTIONS = List.of(
		"otp",
		"webauthn",
		"webauthn-passwordless",
		"email-authenticator",
		"mobile-number"
	);

	/** Required action ids for {@link ConditionalEnforceMfaAuthenticatorFactory} admin UI. */
	public static final List<String> REQUIRED_ACTION_OPTIONS = List.of(
		"CONFIGURE_TOTP",
		"webauthn-register",
		"webauthn-register-passwordless",
		"email-authenticator-setup",
		"mobile_number_config"
	);

	/**
	 * Lit une entrée de config authenticator telle que stockée par l’admin (valeurs jointes avec
	 * {@link Constants#CFG_DELIMITER}).
	 */
	public static List<String> splitMultivalued(Map<String, String> cfg, String key) {
		if (cfg == null) {
			return List.of();
		}
		String v = cfg.get(key);
		if (v == null || v.isBlank()) {
			return List.of();
		}
		return Constants.CFG_DELIMITER_PATTERN.splitAsStream(v)
			.map(String::trim)
			.filter(s -> !s.isEmpty())
			.toList();
	}
}
