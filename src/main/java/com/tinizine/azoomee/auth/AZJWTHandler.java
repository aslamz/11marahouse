package com.tinizine.azoomee.auth;

import static com.tinizine.azoomee.authtoken.signer.AZRequestSignerUtil.TOKEN_HEADER;

import java.security.SignatureException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import net.oauth.jsontoken.Checker;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.discovery.VerifierProviders;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.tinizine.azoomee.auth.data.LoginAuthDAO;
import com.tinizine.azoomee.auth.data.LoginSession;
import com.tinizine.azoomee.authtoken.signer.AZRequestSignerUtil;
import com.tinizine.azoomee.commons.AZServiceConstants;

@Component
public class AZJWTHandler {

	final static Logger LOGGER = LoggerFactory.getLogger(AZJWTHandler.class);
	
	private LoginAuthDAO loginAuthDAO;

	public AZAuthResponse authorizeRequest(AZHttpCachedBodyServletRequest httpRequest) {

		String token = httpRequest.getHeader(TOKEN_HEADER);
		LOGGER.debug("JWT in incoming request=" + token);

		VerifierProviders locators = new VerifierProviders();
		AZVerifierProvider verifierProvider = new AZVerifierProvider(loginAuthDAO);
		locators.setVerifierProvider(SignatureAlgorithm.HS256, verifierProvider);

		JsonTokenParser parser = new JsonTokenParser(locators, getChecker());

		JsonToken jt;
		try {
			jt = parser.verifyAndDeserialize(token);
		} catch (Exception e) {
			LOGGER.error("Error validating the JWT", e);
			return AZAuthResponse.UNAUTHORIZED;
		}
		LOGGER.debug("JWT Verification is Done");
		// at this point the findVerifier is called on the provider and
		// the AuthProfile MUST have been set
		LoginSession loginSession = verifierProvider.getLoginSession();
		
		JsonObject payload = jt.getPayloadAsJsonObject();
		String requestSignature = payload.getAsJsonObject("applicationClaim").getAsJsonPrimitive("signature")
				.getAsString();
		boolean isSignatureValid = verifyRequestSignature(requestSignature, httpRequest, loginSession.getApiSecret());

		LOGGER.debug("Is Request signature valid {}", isSignatureValid);

		if (!isSignatureValid) {
			LOGGER.error("Signature verification failed");
			return AZAuthResponse.UNAUTHORIZED;
		}

		String userId = loginSession.getActorId();
		
		// set the loggedIn headers
		httpRequest.addCustomHeader(AZServiceConstants.X_AZ_LOGGEDINUSER, userId);
		httpRequest.addCustomHeader(AZServiceConstants.X_AZ_AUTHUSER, userId);
		
		return AZAuthResponse.OK;
	}  

	private boolean verifyRequestSignature(String requestSignature, AZHttpCachedBodyServletRequest httpRequest,
			String apiSecret) {

		try {
			// generate a map for headers
			Map<String, String> headerMap = extractHttpHeaders(httpRequest);
			// generate a map for parameters
			Map<String, String> paramsMap = extractHttpParams(httpRequest);

			String resourceURI = httpRequest.getContextPath() + httpRequest.getServletPath();
			LOGGER.debug("Http Method: " + httpRequest.getMethod());
			LOGGER.debug("Resource URI: " + resourceURI);
			LOGGER.debug("Generated headers map: " + headerMap);
			LOGGER.debug("Generated parameters map: " + paramsMap);
			
			String requestBody = httpRequest.getBodyAsString();
			LOGGER.debug("Request Body: '" + requestBody + "'");

			String generatedSignature = new AZRequestSignerUtil().generateRequestSignature(httpRequest.getMethod(),
					resourceURI, paramsMap, headerMap, requestBody, apiSecret);

			LOGGER.debug("Request   Signature : '" + requestSignature + "'");
			LOGGER.debug("Generated Signature : '" + generatedSignature + "'");

			return generatedSignature.equals(requestSignature);
			
		} catch (Exception e) {
			LOGGER.error("Error verifying application signature", e);
		}
		return false;
	}

	private Map<String, String> extractHttpHeaders(AZHttpCachedBodyServletRequest httpRequest) {
		Map<String, String> headerMap = new HashMap<String, String>();

		Enumeration<String> headerNames = httpRequest.getHeaderNames();

		while (headerNames.hasMoreElements()) {
			String headerName = headerNames.nextElement();
			String headerValue = httpRequest.getHeader(headerName);
			headerMap.put(headerName, headerValue);
		}

		return headerMap;
	}

	private Map<String, String> extractHttpParams(AZHttpCachedBodyServletRequest httpRequest) {

		Map<String, String> paramsMap = new HashMap<String, String>();

		Enumeration<String> paramNames = httpRequest.getParameterNames();

		while (paramNames.hasMoreElements()) {
			String paramName = paramNames.nextElement();
			String paramValue = httpRequest.getParameter(paramName);
			paramsMap.put(paramName, paramValue);
		}

		return paramsMap;
	}


	private Checker getChecker() {
		// check whether request has all required attributes in the pay load
		Checker checker = new Checker() {

			@Override
			public void check(JsonObject payload) throws SignatureException {

				// Get the application claim from pay load
				JsonObject applicationClaim = payload.getAsJsonObject("applicationClaim");
				if (applicationClaim == null) {
					LOGGER.error("Token with no application claim");
					throw new SignatureException("No Application Claim Found");
				}

				JsonPrimitive appSignature = applicationClaim.getAsJsonPrimitive("signature");
				if (appSignature == null) {
					LOGGER.error("Token with no custom signature");
					throw new SignatureException("Token with no custom signature");
				}
			}
		};
		return checker;
	}

	@Autowired
	public void setLoginAuthDAO(LoginAuthDAO loginAuthDAO) {
		this.loginAuthDAO = loginAuthDAO;
	}

	

}