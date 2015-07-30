package com.tinizine.azoomee.auth;

import static com.tinizine.azoomee.authtoken.signer.AZRequestSignerUtil.*;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.tinizine.azoomee.commons.AZServiceConstants;

@Component
public class AZJWTVerificationFilter implements Filter {

	final static Logger LOGGER = LoggerFactory.getLogger(AZJWTVerificationFilter.class);

	
	private AZJWTHandler jwtHandler;
	private Pattern whitelistPattern;
	private Integer requestThresholdInSeconds;
	
	private static final int SC_AUTHENTICATION_TIMEOUT = 419;

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		//by-pass for global /error, its internally dispatched
		if (request.getServletPath().equals("/error")) {
			chain.doFilter(req, res);
			return;	
		}
		
		if (whitelistPattern != null && whitelistPattern.matcher(request.getServletPath()).matches()) {
			chain.doFilter(req, res);
			return;
		}
		
		if (checkMaliciousHeaders(request)) {
			LOGGER.error("Incoming request contains AZ banned auth headers");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		
		String jwtToken = request.getHeader(TOKEN_HEADER);

		if (jwtToken == null || jwtToken.trim().length() == 0) {
			LOGGER.error("Request with No Auth Header");
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		
		String reqDateTime = request.getHeader(REQ_TIME_HEADER);
		
		if (!isRequestDateTimeValid(reqDateTime)) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Request Time");
			return;
		}
		
		AZHttpCachedBodyServletRequest httpServletRequest = new AZHttpCachedBodyServletRequest(request);

		AZAuthResponse azAuthResponse = AZAuthResponse.UNAUTHORIZED;
		
		try {
			azAuthResponse = jwtHandler.authorizeRequest(httpServletRequest);
		} catch (Exception e) {
			LOGGER.error("Error verifying Token: ", e);
		}
		
		switch (azAuthResponse) {
			
			case OK: 
				chain.doFilter(httpServletRequest, res);
				break;
			
			case UNAUTHORIZED:
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
				break;
				
			case FORBIDDEN:
				response.sendError(HttpServletResponse.SC_FORBIDDEN);
				break;
			
			case SECRET_EXPIRED:
				response.sendError(SC_AUTHENTICATION_TIMEOUT);
				break;
				
			default:
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
				break;
		}

	}

	public void init(FilterConfig filterConfig) {
	}

	public void destroy() {
	}

	@Autowired
	public void setJwtHandler(AZJWTHandler jwtHandler) {
		this.jwtHandler = jwtHandler;
	}

	@Value("${service.public.urlpatterns}")
	public void setWhiteListedPatterns(String whiteListedPatterns) {
		LOGGER.debug("Public URL Pattern: " + whiteListedPatterns);
		whitelistPattern = Pattern.compile(whiteListedPatterns);
	}
	
	@Value("${service.auth.request.threshold:900}")
	public void setRequestThreshold(String requestThreshold) {
		LOGGER.debug("Request Threshold in secs: " + requestThreshold);
		requestThresholdInSeconds = Integer.valueOf(requestThreshold);
	}
	
	// if any one of the auth headers is present in incoming request, just
	// return that with a bad request
	private boolean checkMaliciousHeaders(HttpServletRequest request) {
		
		return 
				request.getHeader(AZServiceConstants.X_AZ_AUTHPROFILE) != null ||
				request.getHeader(AZServiceConstants.X_AZ_AUTHUSER) != null ||
				request.getHeader(AZServiceConstants.X_AZ_LOGGEDINPROFILE) != null ||
				request.getHeader(AZServiceConstants.X_AZ_LOGGEDINUSER) != null ||
				request.getHeader(AZServiceConstants.X_AZ_LOGGEDINPROFILETYPE) != null;
	}
	
	private boolean isRequestDateTimeValid(String reqDateTime) {
		
		if (reqDateTime == null || reqDateTime.trim().length() == 0) {
			LOGGER.error("Request with No DateTime Header");
			return false;
		}
		// verify if the request was sent within the request threshold seconds
		DateFormat utcFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		utcFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
		try {
			Date reqTime = utcFormat.parse(reqDateTime);
			if (System.currentTimeMillis() - reqTime.getTime() > requestThresholdInSeconds*1000) {
				LOGGER.error("Request was sent before the accepted time limit of {} secs", requestThresholdInSeconds);
				return false;
			} else {
				return true;
			}
		} catch (ParseException e1) {
			LOGGER.error("Invalid Request Date Time Format");
			return false;
		}
	}

	
}
