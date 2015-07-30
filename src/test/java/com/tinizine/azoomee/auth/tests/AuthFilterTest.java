package com.tinizine.azoomee.auth.tests;

import static com.tinizine.azoomee.commons.AZServiceConstants.X_AZ_AUTHUSER;
import static com.tinizine.azoomee.commons.AZServiceConstants.X_AZ_LOGGEDINUSER;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.tinizine.azoomee.auth.AZJWTHandler;
import com.tinizine.azoomee.auth.AZJWTVerificationFilter;
import com.tinizine.azoomee.auth.data.LoginAuthDAO;
import com.tinizine.azoomee.auth.data.LoginSession;
import com.tinizine.azoomee.authtoken.signer.AZJsonWebToken;

public class AuthFilterTest {

	public static final String AUTH_USER = "user-test-001";
	private String requestBody = "{\"name\":\"testbody\"}";

	@Test
	public void testFilterForOKGET() throws IOException, ServletException {

		Map<String, String> authHeaders = generateJWTGET(AUTH_USER);

		LoginAuthDAO loginAuthDAO = Mockito.mock(LoginAuthDAO.class);
		LoginSession loginSession = Mockito.mock(LoginSession.class);

		when(loginSession.getActorId()).thenReturn(AUTH_USER);
		when(loginSession.getApiSecret()).thenReturn("apisecretthatislongenoughtokeepjose4jhappy");

		when(loginAuthDAO.getLoginSession("apikey")).thenReturn(loginSession);

		MockHttpServletRequest request = new MockHttpServletRequest();

		request.setMethod("GET");
		request.setServletPath("/something");
		request.addHeader("Content-Type", "application/json");
		request.addHeader("Host", "localhost");

		Iterator<String> it = authHeaders.keySet().iterator();
		while (it.hasNext()) {
			String key = it.next();
			request.addHeader(key, authHeaders.get(key));
		}

		request.addParameter("test", "true");
		request.addParameter("abc", "123");

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain() {

			@Override
			public void doFilter(ServletRequest req, ServletResponse res) throws IOException, ServletException {
				HttpServletResponse httpResp = (HttpServletResponse) res;
				HttpServletRequest httpReq = (HttpServletRequest) req;
				httpResp.setStatus(200);
				assertEquals(AUTH_USER, httpReq.getHeader(X_AZ_AUTHUSER));
				assertEquals(AUTH_USER, httpReq.getHeader(X_AZ_LOGGEDINUSER));
			}
		};

		AZJWTVerificationFilter authFilter = new AZJWTVerificationFilter();
		AZJWTHandler azJWTHandler = new AZJWTHandler();
		azJWTHandler.setLoginAuthDAO(loginAuthDAO);
		authFilter.setJwtHandler(azJWTHandler);
		authFilter.setRequestThreshold("20");
		authFilter.doFilter(request, response, filterChain);

		assertEquals(200, response.getStatus());
	}
	
	
	@Test
	public void testFilterForOKPOST() throws IOException, ServletException {

		Map<String, String> authHeaders = generateJWTPOST(AUTH_USER);

		LoginAuthDAO loginAuthDAO = Mockito.mock(LoginAuthDAO.class);
		LoginSession loginSession = Mockito.mock(LoginSession.class);

		when(loginSession.getActorId()).thenReturn(AUTH_USER);
		when(loginSession.getApiSecret()).thenReturn("apisecretthatislongenoughtokeepjose4jhappy");

		when(loginAuthDAO.getLoginSession("apikey")).thenReturn(loginSession);

		MockHttpServletRequest request = new MockHttpServletRequest();

		request.setMethod("POST");
		request.setServletPath("/something");
		request.addHeader("Content-Type", "application/json");
		request.addHeader("Host", "localhost");

		request.setContent(requestBody.getBytes());

		Iterator<String> it = authHeaders.keySet().iterator();
		while (it.hasNext()) {
			String key = it.next();
			request.addHeader(key, authHeaders.get(key));
		}

		request.addParameter("test", "true");
		request.addParameter("abc", "123");

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain() {

			@Override
			public void doFilter(ServletRequest req, ServletResponse res) throws IOException, ServletException {
				HttpServletResponse httpResp = (HttpServletResponse) res;
				HttpServletRequest httpReq = (HttpServletRequest) req;
				httpResp.setStatus(200);
				assertEquals(AUTH_USER, httpReq.getHeader(X_AZ_AUTHUSER));
				assertEquals(AUTH_USER, httpReq.getHeader(X_AZ_LOGGEDINUSER));
			}
		};

		AZJWTVerificationFilter authFilter = new AZJWTVerificationFilter();
		AZJWTHandler azJWTHandler = new AZJWTHandler();
		azJWTHandler.setLoginAuthDAO(loginAuthDAO);
		authFilter.setJwtHandler(azJWTHandler);
		authFilter.setRequestThreshold("20");
		authFilter.doFilter(request, response, filterChain);

		assertEquals(200, response.getStatus());
	}
	
	private Map<String, String>  generateJWTPOST(String userId) {
		
		// use the signer library to generate a JWT

		AZJsonWebToken token = new AZJsonWebToken.Builder(userId, "apikey", "apisecretthatislongenoughtokeepjose4jhappy")
				.audience("localhost:3000")
				.method("POST")
				.resourceURI("/something")
				.queryParam("test", "true")
				.queryParam("abc", "123")
				.header("Content-Type", "application/json")
				.header("Host", "localhost")
				.requestBody(requestBody)
				.build();
		Map<String, String> authHeaders = token.signAndReturnAsHttpHeaders();
		return authHeaders;
	}
	
	private Map<String, String>  generateJWTGET(String userId) {
		
		// use the signer library to generate a JWT

		AZJsonWebToken token = new AZJsonWebToken.Builder(userId, "apikey", "apisecretthatislongenoughtokeepjose4jhappy")
				.audience("localhost:3000")
				.method("GET")
				.resourceURI("/something")
				.queryParam("test", "true")
				.queryParam("abc", "123")
				.header("Content-Type", "application/json")
				.header("Host", "localhost")
				.build();
		Map<String, String> authHeaders = token.signAndReturnAsHttpHeaders();
		return authHeaders;
	}

}
