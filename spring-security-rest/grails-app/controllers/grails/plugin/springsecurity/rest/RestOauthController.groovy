/*
 * Copyright 2013-2016 Alvaro Sanchez-Mariscal <alvaro.sanchezmariscal@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package grails.plugin.springsecurity.rest

import grails.plugin.springsecurity.annotation.Secured
import grails.plugin.springsecurity.rest.authentication.RestAuthenticationEventPublisher
import grails.plugin.springsecurity.rest.error.CallbackErrorHandler
import grails.plugin.springsecurity.rest.token.AccessToken
import grails.plugin.springsecurity.rest.token.rendering.AccessTokenJsonRenderer
import grails.plugin.springsecurity.rest.token.storage.TokenStorageService
import groovy.util.logging.Slf4j
import org.apache.commons.codec.binary.Base64
import grails.core.GrailsApplication
import org.pac4j.core.client.IndirectClient
import org.pac4j.core.context.J2EContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.redirect.RedirectAction
import org.springframework.http.HttpStatus
import org.springframework.security.core.userdetails.User

import java.nio.charset.StandardCharsets

@Slf4j
@Secured(['permitAll'])
class RestOauthController {

    static allowedMethods = [accessToken: 'POST']

    final String CALLBACK_ATTR = "spring-security-rest-callback"

    CallbackErrorHandler callbackErrorHandler
    RestOauthService restOauthService
    GrailsApplication grailsApplication

    TokenStorageService tokenStorageService
    def tokenGenerator
    AccessTokenJsonRenderer accessTokenJsonRenderer
    RestAuthenticationEventPublisher authenticationEventPublisher
    /**
     * Starts the OAuth authentication flow, redirecting to the provider's Login URL. An optional callback parameter
     * allows the frontend application to define the frontend callback URL on demand.
     */
    def authenticate(String provider, String callback) {
        IndirectClient client = restOauthService.getClient(provider)
        WebContext context = new J2EContext(request, response)

        if (callback) {
            try {
                if (Base64.isBase64(callback.getBytes())){
                    callback = new String(callback.decodeBase64(), StandardCharsets.UTF_8)
                }
                log.debug "Trying to store in the HTTP session a user specified callback URL: ${callback}"
                session[CALLBACK_ATTR] = new URL(callback).toString()
            } catch (MalformedURLException mue) {
                log.warn "The URL is malformed, is it base64 encoded? Not storing it."
            }
        }

        RedirectAction redirectAction = client.getRedirectAction(context)
        log.debug "Redirecting to ${redirectAction.location}"
        redirect url: redirectAction.location
    }

    /**
     * Handles the OAuth provider callback. It uses {@link RestOauthService} to generate and store a token for that user,
     * and finally redirects to the configured frontend callback URL, where the token is in the URL. That way, the
     * frontend application can store the REST API token locally for subsequent API calls.
     */
    def callback(String provider) {
        WebContext context = new J2EContext(request, response)
        def frontendCallbackUrl
        if (session[CALLBACK_ATTR]) {
            log.debug "Found callback URL in the HTTP session"
            frontendCallbackUrl = session[CALLBACK_ATTR]
        } else {
            log.debug "Found callback URL in the configuration file"
            frontendCallbackUrl = grailsApplication.config.grails.plugin.springsecurity.rest.oauth.frontendCallbackUrl
        }

        try {
            String tokenValue = restOauthService.storeAuthentication(provider, context)
            frontendCallbackUrl = getCallbackUrl(frontendCallbackUrl, tokenValue)

        } catch (Exception e) {
            def errorParams = new StringBuilder()

            Map params = callbackErrorHandler.convert(e)
            params.each { key, value ->
                errorParams << "&${key}=${value.encodeAsURL()}"
            }

            frontendCallbackUrl = getCallbackUrl(frontendCallbackUrl, errorParams.toString())
        }

        log.debug "Redirecting to ${frontendCallbackUrl}"
        redirect url: frontendCallbackUrl
    }

    private String getCallbackUrl(baseUrl, String queryStringSuffix) {
        session[CALLBACK_ATTR] = null
        baseUrl instanceof Closure ? baseUrl(queryStringSuffix) : baseUrl + queryStringSuffix
    }

    /**
     * Generates a new access token given the refresh token passed
     */
    def accessToken() {
        String grantType = params['grant_type']
        if (!grantType || grantType != 'refresh_token') {
            render status: HttpStatus.BAD_REQUEST, text: "Invalid grant_type"
            return
        }

        String refreshToken = params['refresh_token']
        log.debug "Trying to generate an access token for the refresh token: ${refreshToken}"
        if (refreshToken) {
            try {
                def user = tokenStorageService.loadUserByToken(refreshToken)
                User principal = user ? user as User : null
                log.debug "Principal found for refresh token: ${principal}"

                def generateRefreshToken = grailsApplication.config.grails.plugin.springsecurity.rest.token.storage.jwt.generateNewRefreshTokenOnRefresh

                AccessToken accessToken = tokenGenerator.generateAccessToken(principal, generateRefreshToken)

                if (!generateRefreshToken) {
                    accessToken.refreshToken = refreshToken
                }

                authenticationEventPublisher.publishTokenCreation(accessToken)

                response.addHeader 'Cache-Control', 'no-store'
                response.addHeader 'Pragma', 'no-cache'
                render contentType: 'application/json', encoding: 'UTF-8',  text:  accessTokenJsonRenderer.generateJson(accessToken)
            } catch (exception) {
                render status: HttpStatus.FORBIDDEN
            }
        } else {
            log.debug "Refresh token is missing. Replying with bad request"
            render status: HttpStatus.BAD_REQUEST, text: "Refresh token is required"
        }
    }



}
