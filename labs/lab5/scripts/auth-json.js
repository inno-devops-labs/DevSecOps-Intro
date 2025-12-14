// JSON-based login HTTP Sender script for Juice Shop
// Fixed: Explicit variable declaration to prevent ReferenceError

var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var URI = Java.type("org.apache.commons.httpclient.URI");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

var LOGIN_URL_PATH = "/rest/user/login";
var TARGET_BASE = "http://localhost:3000";

function sendingRequest(msg, initiator, helper) {
    // Declare all variables at function scope to ensure they exist
    var url = msg.getRequestHeader().getURI().toString();
    var token = null;
    var loginMsg = null; 
    var sender = null;
    var body = null;
    var responseBody = null;
    var jsonResp = null;

    // 1. RECURSION GUARD: Do not intercept the login request itself
    if (url.indexOf(LOGIN_URL_PATH) >= 0) {
        return;
    }

    // 2. TARGET GUARD: Only run for the specific target
    if (!url.startsWith(TARGET_BASE)) {
        return;
    }

    try {
        // 3. Check for existing global token (Thread-safe)
        token = ScriptVars.getGlobalVar("juice-shop-token");

        if (!token) {
            print("DEBUG: No token found. Attempting to log in...");

            var loginUrl = TARGET_BASE + LOGIN_URL_PATH;
            var email = "admin@juice-sh.op";
            var password = "admin123";

            // Initialize loginMsg explicitly
            loginMsg = new HttpMessage();

            // Build request
            var requestUri = new URI(loginUrl, false);
            var requestHeader = new HttpRequestHeader(HttpRequestHeader.POST, requestUri, HttpHeader.HTTP11);
            requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
            loginMsg.setRequestHeader(requestHeader);

            body = '{"email":"' + email + '","password":"' + password + '"}';
            loginMsg.setRequestBody(body);
            loginMsg.getRequestHeader().setContentLength(loginMsg.getRequestBody().length());

            // Send request
            sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
            sender.sendAndReceive(loginMsg, true);

            // Parse response
            responseBody = loginMsg.getResponseBody().toString();
            
            // Extract token
            try {
                jsonResp = JSON.parse(responseBody);
                if (jsonResp && jsonResp.authentication && jsonResp.authentication.token) {
                    token = jsonResp.authentication.token;
                } else if (jsonResp && jsonResp.token) {
                    token = jsonResp.token;
                }
            } catch (jsonEx) {
                print("ERROR: Failed to parse JSON: " + jsonEx);
            }

            if (token) {
                ScriptVars.setGlobalVar("juice-shop-token", token);
                print("DEBUG: Login successful. Token obtained.");
            } else {
                print("ERROR: Login succeeded but no token found.");
            }
        }

        // 4. Inject Token if available
        if (token) {
            msg.getRequestHeader().setHeader("Authorization", "Bearer " + token);
        }

    } catch (e) {
        print("CRITICAL ERROR in auth-json.js: " + e);
    }
}

function responseReceived(msg, initiator, helper) {
    
}

