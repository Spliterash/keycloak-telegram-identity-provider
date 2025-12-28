package ru.spliterash.keycloakTelegram;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
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
import java.util.List;

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
            MultivaluedMap<String, String> parameters = request.getHttpRequest().getUri().getQueryParameters();
            List<String> telegramParams = parameters.get("telegram");
            String telegram = telegramParams != null ? telegramParams.stream().findFirst().orElse(null) : null;

            if (telegram != null) {
                // Telegram data is present (normal login flow from login page with widget)
                final UriBuilder uriBuilder = UriBuilder.fromUri(request.getRedirectUri());
                uriBuilder
                        .queryParam("state", request.getState().getEncoded())
                        .queryParam("telegram", telegram);
                return Response.temporaryRedirect(uriBuilder.build()).build();
            } else {
                // Telegram data is not present (account linking flow)
                // Show a page with the Telegram widget
                return buildTelegramWidgetPage(request);
            }
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    private Response buildTelegramWidgetPage(AuthenticationRequest request) {
        String redirectUri = request.getRedirectUri();
        String state = request.getState().getEncoded();
        String botName = getConfig().getAlias();

        String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Telegram Login</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            min-height: 100vh;
                            margin: 0;
                            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        }
                        .container {
                            background: white;
                            padding: 40px;
                            border-radius: 16px;
                            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                            text-align: center;
                        }
                        h2 {
                            color: #333;
                            margin-bottom: 24px;
                        }
                        .telegram-widget {
                            display: inline-block;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Link your Telegram account</h2>
                        <div class="telegram-widget">
                            <script async src="https://telegram.org/js/telegram-widget.js?22"
                                    data-telegram-login="%s"
                                    data-size="large"
                                    data-onauth="onTelegramAuth(user)"
                                    data-request-access="write"></script>
                        </div>
                    </div>
                    <script>
                        function onTelegramAuth(user) {
                            const redirectUri = "%s";
                            const state = "%s";
                            const telegramData = encodeURIComponent(utf8ToBase64(JSON.stringify(user)));
                            window.location.href = redirectUri + "?state=" + encodeURIComponent(state) + "&telegram=" + telegramData;
                        }
                        function utf8ToBase64(str) {
                            const utf8Bytes = new TextEncoder().encode(str);
                            return btoa(String.fromCharCode(...utf8Bytes));
                        }
                    </script>
                </body>
                </html>
                """.formatted(escapeJs(botName), escapeJs(redirectUri), escapeJs(state));

        return Response.ok(html, MediaType.TEXT_HTML_TYPE).build();
    }

    private String escapeJs(String input) {
        if (input == null) return "";
        return input
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("'", "\\'")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
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
