package com.tinizine.azoomee.auth;

import java.security.InvalidKeyException;
import java.util.List;

import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.tinizine.azoomee.auth.data.LoginAuthDAO;
import com.tinizine.azoomee.auth.data.LoginSession;

public class AZVerifierProvider implements VerifierProvider {

	final static Logger LOGGER = LoggerFactory.getLogger(AZVerifierProvider.class);

	private LoginAuthDAO loginAuthDAO;
	private LoginSession loginSession;
	
	protected AZVerifierProvider() {

	}

	public AZVerifierProvider(LoginAuthDAO loginAuthDAO) {
		this.loginAuthDAO = loginAuthDAO;
	}

	public List<Verifier> findVerifier(String issuer, String key) {
		List<Verifier> verfiers = Lists.newArrayList();
		LOGGER.debug("Issuer of this token : " + issuer + " And Key : " + key);

		try {
			LoginSession loginSession = loginAuthDAO.getLoginSession(key);
			if (loginSession != null && loginSession.getActorId().equals(issuer)) {
				LOGGER.debug("Auth Profile available for this issuer and key");
				this.loginSession = loginSession;
				Verifier hmacVerifier = new HmacSHA256Verifier(loginSession.getApiSecret().getBytes());
				verfiers.add(hmacVerifier);
			}

		} catch (InvalidKeyException e) {
			LOGGER.error("Invalid Key Provided", e);
		}

		return verfiers;
	}

	public LoginSession getLoginSession() {
		return this.loginSession;
	}

}
