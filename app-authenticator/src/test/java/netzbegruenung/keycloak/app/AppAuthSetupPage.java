package netzbegruenung.keycloak.app;

import org.keycloak.testframework.ui.page.AbstractLoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 * app-auth-setup.ftl - the QR-code / action-token page for the app-register required action.
 * The page's own JS auto-submits {@code kc-app-authentication} once an SSE "ready" event
 * arrives, but SSE is a non-functional stub under the HtmlUnit WebDriver this framework uses
 * by default, so the test submits the form directly instead of waiting on that JS.
 */
public class AppAuthSetupPage extends AbstractLoginPage {

	@FindBy(name = "actiontoken")
	private WebElement actionTokenInput;

	@FindBy(id = "kc-app-authentication")
	private WebElement form;

	public AppAuthSetupPage(ManagedWebDriver driver) {
		super(driver);
	}

	@Override
	public String getExpectedPageId() {
		return "login-app-auth-setup";
	}

	public String getActionTokenUrl() {
		return actionTokenInput.getAttribute("value");
	}

	/**
	 * Submits via JS rather than {@code WebElement.submit()}: the latter follows the WebDriver
	 * spec's "activate the form's default submit button" semantics, which - when this action was
	 * triggered as an application-initiated action (kc_action) - is the template's "cancel-aia"
	 * button (the only other one is type="button", not a submit control), incorrectly cancelling
	 * the action instead of completing it. A JS-level submit(), like the page's own SSE-triggered
	 * auto-submit, never activates any button.
	 */
	public void submit() {
		((JavascriptExecutor) driver.driver()).executeScript("arguments[0].submit();", form);
	}
}
