package com.odobo.grails.plugin.springsecurity.rest.token.storage

import grails.plugin.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.commons.GrailsApplication

class RedisTokenStorageService implements TokenStorageService {

    def redisService
    def userDetailsService

    private static final String PREFIX = "spring:security:token:"

    @Override
    Object loadUserByToken(String tokenValue) throws com.odobo.grails.plugin.springsecurity.rest.token.storage.TokenNotFoundException {
        def username
        redisService.withRedis { jedis ->
            username = jedis.get(buildKey(tokenValue))
        }
        if (username) {
            return userDetailsService.loadUserByUsername(username)
        }

        throw new com.odobo.grails.plugin.springsecurity.rest.token.storage.TokenNotFoundException("Token ${tokenValue} not found")
    }

    @Override
    void storeToken(String tokenValue, Object principal) {
        redisService.withRedis { jedis ->
            String key = buildKey(tokenValue)
            jedis.set(key, principal.username.toString())
            jedis.expire(key, conf.expiration ?: 3600)
        }
    }

    @Override
    void removeToken(String tokenValue) throws com.odobo.grails.plugin.springsecurity.rest.token.storage.TokenNotFoundException {
        redisService.del(buildKey(tokenValue))
    }

    private static String buildKey(String token){
        "$PREFIX$token"
    }

    private static def getConf(){
        SpringSecurityUtils.securityConfig.rest.token.storage.redis
    }
}
