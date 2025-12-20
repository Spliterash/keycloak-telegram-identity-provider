package ru.spliterash.keycloakTelegram;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.sessions.AuthenticationSessionModel;
import ru.spliterash.keycloakTelegram.model.TelegramAuthData;
import ru.spliterash.keycloakTelegram.model.TelegramWebAuthenticatorConfig;
import ru.spliterash.keycloakTelegram.validator.TelegramAuthDataValidator;

import java.io.IOException;
import java.util.Base64;

@JBossLog
public class TelegramWebLoginWidgetIdentityProvider extends AbstractIdentityProvider<TelegramWebAuthenticatorConfig> {
    public static final String TG_USER_PHOTO_URL_ATTRIBUTE_NAME = "TELEGRAM_PHOTO_URL";
    private final ObjectMapper mapper = new ObjectMapper();

    public TelegramWebLoginWidgetIdentityProvider(KeycloakSession session, TelegramWebAuthenticatorConfig config) {
        super(session, config);
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        throw new IllegalStateException("Telegram do not provide user tokens");
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            final UriBuilder uriBuilder = UriBuilder.fromUri(request.getRedirectUri());
            MultivaluedMap<String, String> parameters = request.getHttpRequest().getUri().getQueryParameters();
            String telegram = parameters.get("telegram").stream().findFirst().orElse(null);
            uriBuilder
                    .queryParam("state", request.getState().getEncoded())
                    .queryParam("telegram", telegram);

            return Response.temporaryRedirect(uriBuilder.build()).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, event, session, this);
    }

    @RequiredArgsConstructor
    private static class Endpoint {
        private final AuthenticationCallback callback;
        private final EventBuilder event;
        private final KeycloakSession session;
        private final TelegramWebLoginWidgetIdentityProvider self;

        @GET
        @Path("/")
        public Response authenticate(
                @QueryParam("state") String state,
                @QueryParam("telegram") String telegram
        ) {
            TelegramAuthData telegramAuthData;
            try {
                telegramAuthData = self.mapper.readValue(Base64.getDecoder().decode(telegram), TelegramAuthData.class);
            } catch (IOException e) {
                return errorIdentityProviderLogin(e.getMessage());
            }
            AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);

            session.getContext().setAuthenticationSession(authSession);

            TelegramWebAuthenticatorConfig authenticatorConfig = self.getConfig();


            TelegramAuthDataValidator telegramAuthDataValidator = new TelegramAuthDataValidator(authenticatorConfig, telegramAuthData);
            if (!telegramAuthDataValidator.isValid()) return callback.cancelled(authenticatorConfig);

            BrokeredIdentityContext context = getBrokeredIdentityContext(telegramAuthData, authenticatorConfig, authSession);
            var photoUrl = telegramAuthData.photoUrl();
            if (photoUrl != null)
                context.setUserAttribute(TG_USER_PHOTO_URL_ATTRIBUTE_NAME, photoUrl);

            return callback.authenticated(context);
        }

        private BrokeredIdentityContext getBrokeredIdentityContext(
                TelegramAuthData telegramAuthData,
                TelegramWebAuthenticatorConfig authenticatorConfig,
                AuthenticationSessionModel authSession
        ) {
            BrokeredIdentityContext context = new BrokeredIdentityContext(telegramAuthData.id(), authenticatorConfig);
            String username = telegramAuthData.username();
            if (username == null || username.isBlank())
                username = "tg." + telegramAuthData.id();
            context.setUsername(username);
            context.setFirstName(telegramAuthData.firstName());
            context.setLastName(telegramAuthData.lastName());
            context.setIdp(self);
            context.setAuthenticationSession(authSession);
            return context;
        }


        private Response errorIdentityProviderLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }
    }

    @Override
    public void close() {
        // no-op
    }
}
