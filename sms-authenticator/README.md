# Keycloak 2FA SMS Authenticator

Keycloak Authentication Provider implementation to get a 2nd-factor authentication with a OTP/code/token send via SMS with a configurable HTTPS API.
It should be possible to interact with most SMS providers. Issues and pull requests to support more SMS providers are welcome.

This is a fork of a great demo implementation by [@dasniko](https://github.com/dasniko/keycloak-2fa-sms-authenticator), and also takes huge chunks of code
from the original authenticator provider [documentation](https://www.keycloak.org/docs/latest/server_development/index.html#_auth_spi) and [example](https://github.com/keycloak/keycloak/tree/main/examples/providers/authenticator) from Keycloak itself.

# Installing
1. Go to https://github.com/netzbegruenung/keycloak-mfa-plugins/releases and download
   the latest .jar file.
1. Copy the created jar file into the `providers` directory of your Keycloak:
   ```shell
   cp netzbegruenung.keycloak-2fa-sms-authenticator.jar /path/to/keycloak/providers
   ```
1. Run the `build` command and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   systemctl restart keycloak.service
   ```

## Where configuration lives

| What | Where |
|------|--------|
| **Login** (browser flow, step *SMS Authentication (2FA)*) | Optional config on that execution. If the step has **no** config, Keycloak uses the **same base map** as registration (see below), then merges any execution config on top so **per-step values win**. |
| **Registration** (required actions *Update Mobile Number* / *Phone Validation*) | **Option A:** settings on *Update Mobile Number* (gear). **Option B:** leave those empty and use a realm authenticator config by alias (see *Phone registration* below). |

## Phone registration: where do SMS settings come from?

When users **add or confirm a mobile number** (required actions *Update Mobile Number* and *Phone Validation*), the plugin needs the same kind of settings as for login SMS (API URL, code length, TTL, provider-specific fields). You can supply them in **two ways**; pick one as your main approach.

### Option A — All in the required action (good default for new projects)

1. Open **Authentication → Required actions**.
1. Open **Update Mobile Number** → **Settings** (gear icon).
1. Fill the SMS fields (same labels as for the *SMS Authentication (2FA)* authenticator in a flow).

As soon as **SMS API URL**, **Code length**, or **Time-to-live** is non-empty, **registration** uses **only** this screen. Empty fields use the same defaults as the authenticator factory. You do **not** need a separate “registration-only” authenticator config for this path.

### Option B — Reuse a realm authenticator config (legacy / upgrades)

Leave **SMS API URL**, **Code length**, and **Time-to-live** **empty** on *Update Mobile Number*. Registration then loads the **realm authenticator configuration** (a named block of settings in Keycloak) whose **alias** is **`sms-2fa`** — the same **Authenticator config** you create in the admin UI under **Authentication → Flows** (e.g. Browser flow) on the **SMS Authentication (2FA)** step, or via realm import/API. Several executions can reference the same config; registration resolves it **by that fixed alias**, not by “which flow you edited last”.

> **Why `sms-2fa`?** Older setups and docs used a single realm config with that alias, often created from the browser flow’s SMS step. Keeping it as the default avoids breaking upgrades. New installs can ignore it if they use **Option A** only.

## First-time checklist

1. *Authentication → Required actions*: enable **Phone Validation** and **Update Mobile Number**.
1. *Authentication → Flows* (e.g. **Browser**): add step **SMS Authentication (2FA)** (often **Alternative** next to OTP).
1. Configure SMS for your provider using **one** main approach:
   - **Option A:** required action *Update Mobile Number* (gear), or  
   - **Option B:** authenticator config in a flow (alias `sms-2fa`) if the required action SMS fields stay empty, and/or  
   - **Per-flow login overrides:** config on the SMS **execution** in the flow when that flow needs different values for **login**.
1. For **login**, if the SMS step has no config, it reuses the same effective map as registration; attach a config on the step only when that flow needs different values.

## Usage

Users configure SMS in the account console, e.g.  
`/realms/<realm>/account/#/account-security/signing-in` — enter and confirm the mobile number.

## Enforce SMS 2FA

If **Force 2FA** is enabled in the **effective registration** configuration (Option A map on the required action, or Option B authenticator config) and the user has no other second factor yet, they are pushed to set up SMS (or another allowed required action).
