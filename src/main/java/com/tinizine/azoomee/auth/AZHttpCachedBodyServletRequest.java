package com.tinizine.azoomee.auth;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import com.google.common.io.ByteStreams;
import com.google.common.io.CharStreams;


public class AZHttpCachedBodyServletRequest extends HttpServletRequestWrapper {
	
	private byte[] body;
	
	private Map<String, String> customHeaders;

	public AZHttpCachedBodyServletRequest(HttpServletRequest request) throws IOException {
		super(request);
		customHeaders = new HashMap<String,String>();
		InputStream is = super.getInputStream();
		body = ByteStreams.toByteArray(is);
	}
	
	@Override
	public ServletInputStream getInputStream() {
		return new AZServletInputStream(new ByteArrayInputStream(body));
	}

	@Override
	public BufferedReader getReader() throws IOException {
		String enc = getCharacterEncoding();
		if(enc == null) {
			enc = "UTF-8";
		}
		return new BufferedReader(new InputStreamReader(getInputStream(), enc));
	}
	
	public String getBodyAsString() throws IOException {
		return CharStreams.toString(getReader());
	}
	
	public String getHeader(String name) {
		String headerValue = customHeaders.get(name);
		if (headerValue != null){
			return headerValue;
		}
		return ((HttpServletRequest) getRequest()).getHeader(name);
	}
 
	public Enumeration<String> getHeaderNames() {
		Set<String> set = new HashSet<String>(customHeaders.keySet());
		
		Enumeration<String> e = ((HttpServletRequest) getRequest()).getHeaderNames();
		while (e.hasMoreElements()) {
			set.add(e.nextElement());
		}
 		return Collections.enumeration(set);
	}
	
	public void addCustomHeader(String name, String value){
		this.customHeaders.put(name, value);
	}

}
