package com.tinizine.azoomee.auth.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;


public class LoginSession {
	
	private String actorId;
	private String apiKey;
	private String apiSecret;
	
	protected LoginSession() {
		
	}
	
	@JsonCreator
	public LoginSession(@JsonProperty("actorId") String actorId, @JsonProperty("apiKey") String apiKey, @JsonProperty("apiSecret") String apiSecret) {
		this.actorId = actorId;
		this.apiKey = apiKey;
		this.apiSecret = apiSecret;
	}

	
	public String getActorId() {
		return actorId;
	}
	
	public String getApiKey() {
		return apiKey;
	}

	public String getApiSecret() {
		return apiSecret;
	}

	
}
