package com.tinizine.azoomee.auth.data;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

public class LoginAuthDAOImpl implements LoginAuthDAO {
	
	final static Logger LOGGER = LoggerFactory.getLogger(LoginAuthDAOImpl.class);

    RedisTemplate<String, LoginSession> redisTemplate; 

    public static final String OBJECT_KEY = "LOGIN";

    public LoginAuthDAOImpl(JedisConnectionFactory jedisConnectionFactory) {
    	this.redisTemplate = new RedisTemplate<String, LoginSession>();
		this.redisTemplate.setConnectionFactory(jedisConnectionFactory);
		this.redisTemplate.setEnableDefaultSerializer(false);
		this.redisTemplate.setKeySerializer(new StringRedisSerializer());		
		this.redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(LoginSession.class));
		this.redisTemplate.afterPropertiesSet();
    }
    
    
    public LoginSession getLoginSession(String apiKey) {
    	LoginSession loginSession = redisTemplate.boundValueOps(OBJECT_KEY + "|" + apiKey).get();    	
    	return loginSession;
    }

}
