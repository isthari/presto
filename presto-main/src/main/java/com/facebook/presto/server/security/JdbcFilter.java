/*
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
 */

/*
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
 */
package com.facebook.presto.server.security;

import com.google.common.base.Splitter;
import com.google.common.net.HttpHeaders;
import io.airlift.http.client.HttpStatus;
import io.airlift.log.Logger;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import static com.google.common.base.MoreObjects.toStringHelper;
import static com.google.common.io.ByteStreams.copy;
import static com.google.common.io.ByteStreams.nullOutputStream;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static io.airlift.http.client.HttpStatus.BAD_REQUEST;
import static io.airlift.http.client.HttpStatus.UNAUTHORIZED;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

public class JdbcFilter
        implements Filter
{
    private static final Logger log = Logger.get(JdbcFilter.class);

    private static final String BASIC_AUTHENTICATION_PREFIX = "Basic ";

    private Pattern bcryptPattern = Pattern
            .compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");

    private String jdbcUrl;
    private String jdbcUsername;
    private String jdbcPassword;

    @Inject
    public JdbcFilter(JdbcConfig serverConfig)
    {
        log.info("Init jdbc filter");
        this.jdbcUrl = requireNonNull(serverConfig.getJdbcUrl(), "jdbcUrl is null");
        this.jdbcUsername = requireNonNull(serverConfig.getJdbcUsername(), "jdbcUsername is null");
        this.jdbcPassword = requireNonNull(serverConfig.getJdbcPassword(), "jdbcPassword is null");
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}
    @Override
    public void destroy() {}

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain nextFilter) throws IOException, ServletException
    {
        // skip auth for http
        if (!servletRequest.isSecure()) {
            nextFilter.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        try {
            String header = request.getHeader(AUTHORIZATION);
            Credentials credentials = getCredentials(header);
            Principal principal = authenticate(credentials);

            // jdbc authentication ok, continue
            nextFilter.doFilter(new HttpServletRequestWrapper(request)
            {
                @Override
                public Principal getUserPrincipal()
                {
                    return principal;
                }
            }, servletResponse);
        }
        catch (AuthenticationException e) {
            log.info("JDBC authentication failed", e);
            processAuthenticationException(e, request, response);
        }
    }

    private Principal authenticate(Credentials credentials)
            throws AuthenticationException
    {
        // TODO hacer cache de los usuarios para no tener que volver a comprobar
        String user = credentials.getUser();
        String password = credentials.getPassword();

        try (Connection con = DriverManager.getConnection(jdbcUrl, jdbcUsername, jdbcPassword)) {
            log.info("username: " + user + " password: " + password);
            PreparedStatement prepared = con.prepareStatement("select password from user where email=?");
            prepared.setString(1, user);
            ResultSet rs = prepared.executeQuery();
            if (rs.next()) {
                String encryptedPassword = rs.getString("password");
                if (matches(password, encryptedPassword)) {
                    log.info("Match");
                    Principal principal = new JdbcPrincipal(user);
                    return principal;
                }
                else {
                    log.info("Password doesn't match");
                }
            }
            else {
                log.info("Username not found");
                throw new AuthenticationException(UNAUTHORIZED, "username not found: " + user);
            }
        }
        catch (SQLException e) {
            throw new AuthenticationException(UNAUTHORIZED, e.getMessage());
        }
        throw new AuthenticationException(UNAUTHORIZED, "");
    }

    private boolean matches(CharSequence rawPassword, String encodedPassword)
    {
        if (encodedPassword == null || encodedPassword.length() == 0) {
            log.warn("Empty encoded password");
            return false;
        }

        if (!bcryptPattern.matcher(encodedPassword).matches()) {
            log.warn("Encoded password does not look like BCrypt");
            return false;
        }

        return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
    }

    private static void processAuthenticationException(AuthenticationException e, HttpServletRequest request, HttpServletResponse response)
            throws IOException
    {
        if (e.getStatus() == UNAUTHORIZED) {
            // If we send the challenge without consuming the body of the request,
            // the Jetty server will close the connection after sending the response.
            // The client interprets this as a failed request and does not resend
            // the request with the authentication header.
            // We can avoid this behavior in the Jetty client by reading and discarding
            // the entire body of the unauthenticated request before sending the response.
            skipRequestBody(request);
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"presto\"");
        }
        response.sendError(e.getStatus().code(), e.getMessage());
    }
    private static void skipRequestBody(HttpServletRequest request)
            throws IOException
    {
        try (InputStream inputStream = request.getInputStream()) {
            copy(inputStream, nullOutputStream());
        }
    }

    private static Credentials getCredentials(String header)
            throws AuthenticationException
    {
        if (header == null) {
            throw new AuthenticationException(UNAUTHORIZED, "Unauthorized");
        }
        if (!header.startsWith(BASIC_AUTHENTICATION_PREFIX)) {
            throw new AuthenticationException(BAD_REQUEST, "Basic authentication is expected");
        }
        String base64EncodedCredentials = header.substring(BASIC_AUTHENTICATION_PREFIX.length());
        String credentials = decodeCredentials(base64EncodedCredentials);
        List<String> parts = Splitter.on(':').limit(2).splitToList(credentials);
        if (parts.size() != 2 || parts.stream().anyMatch(String::isEmpty)) {
            throw new AuthenticationException(BAD_REQUEST, "Malformed decoded credentials");
        }
        return new Credentials(parts.get(0), parts.get(1));
    }
    private static String decodeCredentials(String base64EncodedCredentials)
            throws AuthenticationException
    {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(base64EncodedCredentials);
        }
        catch (IllegalArgumentException e) {
            throw new AuthenticationException(BAD_REQUEST, "Invalid base64 encoded credentials");
        }
        return new String(bytes, UTF_8);
    }

    private static class Credentials
    {
        private final String user;
        private final String password;

        private Credentials(String user, String password)
        {
            this.user = requireNonNull(user);
            this.password = requireNonNull(password);
        }

        public String getUser()
        {
            return user;
        }
        public String getPassword()
        {
            return password;
        }

        @Override
        public String toString()
        {
            return toStringHelper(this)
                    .add("user", user)
                    .add("password", password)
                    .toString();
        }
    }

    private class JdbcPrincipal
            implements Principal
    {
        private String name;

        public JdbcPrincipal(String name)
        {
            this.name = name;
        }

        @Override
        public String getName()
        {
            return name;
        }
    }

    private static class AuthenticationException
            extends Exception
    {
        private final HttpStatus status;

        private AuthenticationException(HttpStatus status, String message)
        {
            this(status, message, null);
        }

        private AuthenticationException(HttpStatus status, String message, Throwable cause)
        {
            super(message, cause);
            requireNonNull(message, "message is null");
            this.status = requireNonNull(status, "status is null");
        }

        public HttpStatus getStatus()
        {
            return status;
        }
    }
}
