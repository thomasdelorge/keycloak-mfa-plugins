package netzbegruenung.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves SMS settings for required actions (mobile number capture and validation). Those run outside
 * an authentication execution, so they cannot use {@code AuthenticationFlowContext#getAuthenticatorConfig()}.
 * <p>
 * <strong>Inline mode (new)</strong>: set SMS fields on the &quot;Update Mobile Number&quot; required action
 * (Authentication → Required actions → settings). When {@link #isInlineSmsRegistration(Map)} is true for that
 * config, registration uses those values (defaults fill missing keys). No browser-flow authenticator config is
 * required for registration.
 * <p>
 * <strong>Legacy fallback</strong>: otherwise load the realm {@linkplain AuthenticatorConfigModel authenticator config}
 * with alias {@value #LEGACY_DEFAULT_ALIAS} (historical default used when creating the SMS step in a flow).
 * <p>
 * Realm attributes {@value #REALM_ATTR_OVERRIDE_PREFIX}&lt;key&gt; still override individual keys on top of either source.
 */
public final class SmsRegistrationConfigResolver {

	private static final Logger LOG = Logger.getLogger(SmsRegistrationConfigResolver.class);

	public static final String REALM_ATTR_OVERRIDE_PREFIX = "smsAuthenticator.registrationOverride.";

	public static final String LEGACY_DEFAULT_ALIAS = "sms-2fa";

	/** Factory defaults for OTP length and TTL when absent from legacy authenticator config or overrides. */
	public static final String DEFAULT_LENGTH = "6";
	public static final String DEFAULT_TTL_SECONDS = "300";

	private SmsRegistrationConfigResolver() {}

	/**
	 * {@code true} when the required-action map carries explicit SMS registration settings so flow-bound
	 * authenticator config is not required for registration.
	 */
	public static boolean isInlineSmsRegistration(Map<String, String> ra) {
		if (ra == null || ra.isEmpty()) {
			return false;
		}
		return hasNonBlank(ra, "apiurl") || hasNonBlank(ra, "length") || hasNonBlank(ra, "ttl");
	}

	private static boolean hasNonBlank(Map<String, String> m, String k) {
		String v = m.get(k);
		return v != null && !v.isBlank();
	}

	/** Raw config from the &quot;Update Mobile Number&quot; required action (empty map if none). */
	public static Map<String, String> readPhoneNumberRequiredActionConfig(RealmModel realm) {
		Map<String, String> cfg = realm.getRequiredActionProvidersStream()
			.filter(p -> PhoneNumberRequiredAction.PROVIDER_ID.equals(p.getProviderId()))
			.findFirst()
			.map(RequiredActionProviderModel::getConfig)
			.orElse(null);
		if (cfg == null || cfg.isEmpty()) {
			return Map.of();
		}
		return new HashMap<>(cfg);
	}

	/**
	 * Fixed alias for legacy (non-inline) registration: authenticator config created on the SMS flow step.
	 *
	 * @param realm ignored; kept for call-site stability
	 */
	@SuppressWarnings("unused")
	public static String resolveRegistrationConfigAlias(RealmModel realm) {
		return LEGACY_DEFAULT_ALIAS;
	}

	public static Map<String, String> getMergedRegistrationConfig(RealmModel realm) {
		Map<String, String> ra = readPhoneNumberRequiredActionConfig(realm);
		Map<String, String> merged = new HashMap<>();
		if (isInlineSmsRegistration(ra)) {
			merged.putAll(buildInlineRegistrationConfig(ra));
		} else {
			String alias = resolveRegistrationConfigAlias(realm);
			AuthenticatorConfigModel acm = realm.getAuthenticatorConfigByAlias(alias);
			if (acm != null && acm.getConfig() != null) {
				merged.putAll(acm.getConfig());
			}
		}
		applyRealmOverrides(realm, merged);
		ensureOtpLengthAndTtlDefaults(merged);
		return Collections.unmodifiableMap(merged);
	}

	/** Legacy configs may omit keys present in the admin UI by default; align with {@link SmsAuthenticatorFactory} defaults. */
	private static void ensureOtpLengthAndTtlDefaults(Map<String, String> merged) {
		if (merged.isEmpty()) {
			return;
		}
		String length = merged.get("length");
		if (length == null || length.isBlank()) {
			merged.put("length", DEFAULT_LENGTH);
		}
		String ttl = merged.get("ttl");
		if (ttl == null || ttl.isBlank()) {
			merged.put("ttl", DEFAULT_TTL_SECONDS);
		}
	}

	/**
	 * Logs a WARN when the realm still relies on the flow-bound authenticator config {@value #LEGACY_DEFAULT_ALIAS}
	 * for SMS base settings instead of inline fields on the &quot;Update Mobile Number&quot; required action.
	 * Intended to be invoked before each outbound SMS so operators notice legacy setups.
	 */
	public static void logWarningIfUsingLegacySmsAuthenticatorConfig(RealmModel realm) {
		if (isInlineSmsRegistration(readPhoneNumberRequiredActionConfig(realm))) {
			return;
		}
		AuthenticatorConfigModel legacy = realm.getAuthenticatorConfigByAlias(LEGACY_DEFAULT_ALIAS);
		if (legacy == null || legacy.getConfig() == null || legacy.getConfig().isEmpty()) {
			return;
		}
		LOG.warnf(
			"SMS authenticator plugin: realm \"%s\" still uses legacy authenticator config alias \"%s\" for SMS settings. "
				+ "Migrate to inline settings on required action \"Update Mobile Number\" (Authentication → Required actions → gear icon) to avoid depending on a flow alias.",
			realm.getName(),
			LEGACY_DEFAULT_ALIAS
		);
	}

	/**
	 * Effective SMS key/value map for a browser-flow (or other) execution: starts from the same source as
	 * registration ({@link #getMergedRegistrationConfig(RealmModel)}), then applies the execution-bound
	 * authenticator config on top when present (execution keys override; blank values in execution still overwrite).
	 */
	public static Map<String, String> getEffectiveSmsConfigForExecution(RealmModel realm, AuthenticatorConfigModel executionConfig) {
		Map<String, String> eff = new HashMap<>(getMergedRegistrationConfig(realm));
		if (executionConfig != null && executionConfig.getConfig() != null) {
			eff.putAll(executionConfig.getConfig());
		}
		return eff;
	}

	private static Map<String, String> buildInlineRegistrationConfig(Map<String, String> ra) {
		Map<String, String> out = new HashMap<>();
		for (ProviderConfigProperty p : SmsAuthenticatorFactory.getSmsAuthenticatorConfigProperties()) {
			String k = p.getName();
			if (p.getType() == ProviderConfigProperty.ROLE_TYPE) {
				String v = ra.get(k);
				if (v != null && !v.isBlank()) {
					out.put(k, v);
				}
				continue;
			}
			String v = ra.get(k);
			if (v != null && !v.isBlank()) {
				out.put(k, v);
			} else {
				Object d = p.getDefaultValue();
				if (d == null || d instanceof List) {
					out.put(k, "");
				} else {
					out.put(k, String.valueOf(d));
				}
			}
		}
		return out;
	}

	private static void applyRealmOverrides(RealmModel realm, Map<String, String> merged) {
		Map<String, String> attributes = realm.getAttributes();
		if (attributes == null) {
			return;
		}
		for (Map.Entry<String, String> e : attributes.entrySet()) {
			String key = e.getKey();
			if (key != null && key.startsWith(REALM_ATTR_OVERRIDE_PREFIX) && e.getValue() != null) {
				String prop = key.substring(REALM_ATTR_OVERRIDE_PREFIX.length());
				if (!prop.isBlank()) {
					merged.put(prop, e.getValue());
				}
			}
		}
	}
}
