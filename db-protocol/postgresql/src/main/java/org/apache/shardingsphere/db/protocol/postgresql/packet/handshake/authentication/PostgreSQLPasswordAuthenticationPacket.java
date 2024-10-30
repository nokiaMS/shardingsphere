/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shardingsphere.db.protocol.postgresql.packet.handshake.authentication;

import org.apache.shardingsphere.db.protocol.postgresql.packet.identifier.PostgreSQLIdentifierPacket;
import org.apache.shardingsphere.db.protocol.postgresql.packet.identifier.PostgreSQLIdentifierTag;
import org.apache.shardingsphere.db.protocol.postgresql.packet.identifier.PostgreSQLMessagePacketType;
import org.apache.shardingsphere.db.protocol.postgresql.payload.PostgreSQLPacketPayload;

/**
 * 密码认证包，要求客户端发送密码。
 * Password authentication (backend) packet for PostgreSQL.
 */
public final class PostgreSQLPasswordAuthenticationPacket extends PostgreSQLIdentifierPacket {
    
    private static final int AUTH_REQ_PASSWORD = 3;
    
    @Override
    protected void write(final PostgreSQLPacketPayload payload) {
        payload.writeInt4(AUTH_REQ_PASSWORD);
    }

    /**
     * 返回消息包的表示信息，此处为R。
     * @return
     */
    @Override
    public PostgreSQLIdentifierTag getIdentifier() {
        return PostgreSQLMessagePacketType.AUTHENTICATION_REQUEST;
    }
}
