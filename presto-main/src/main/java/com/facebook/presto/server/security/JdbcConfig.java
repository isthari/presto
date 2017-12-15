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

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;

import javax.validation.constraints.NotNull;

public class JdbcConfig
{
    private String jdbcUrl;
    private String jdbcUsername;
    private String jdbcPassword;

    @NotNull
    public String getJdbcUrl()
    {
        return jdbcUrl;
    }

    @Config("authentication.jdbc.url")
    @ConfigDescription("URL of the database server")
    public JdbcConfig setJdbcUrl(String url)
    {
        this.jdbcUrl = url;
        return this;
    }

    @NotNull
    public String getJdbcUsername()
    {
        return jdbcUsername;
    }

    @Config("authentication.jdbc.username")
    @ConfigDescription("Database username")
    public JdbcConfig setJdbcUsername(String username)
    {
        this.jdbcUsername = username;
        return this;
    }

    @NotNull
    public String getJdbcPassword()
    {
        return jdbcPassword;
    }

    @Config("authentication.jdbc.password")
    @ConfigDescription("Database password")
    public JdbcConfig setJdbcPassword(String password)
    {
        this.jdbcPassword = password;
        return this;
    }
}
