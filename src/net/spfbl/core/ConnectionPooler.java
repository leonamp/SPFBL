/*
 * This file is part of SPFBL.
 *
 * SPFBL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SPFBL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.core;

import com.mysql.jdbc.exceptions.jdbc4.MySQLNonTransientConnectionException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Semaphore;

/**
 * Um pooler para aproveitamento de conexões MySQL.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class ConnectionPooler {

    private final String URL;
    private final String USER;
    private final String PASSWORD;

    private final int MAX_IDLE_TIME = 60000;
    private final Timer TIMER = new Timer("BCKGROUND");
    private final Semaphore SEMAPHORE = new Semaphore(1);
    private Connection CONNECTION = null;

    /**
     * Cria um pooler através dos parametros de conexão.
     * @param hostname endereço do servidor de banco de dados.
     * @param port a porta de conexão com o banco de dados.
     * @param user nome de usuário do banco de dados.
     * @param password senha do banco de dados.
     * @param schema base de dados utilizada.
     * @param ssl se a conexão deve ser criptografada.
     */
    protected ConnectionPooler(
            String hostname,
            short port,
            String user,
            String password,
            String schema,
            boolean ssl
            ) {
        this.URL = "jdbc:mysql://" + hostname + ":"
                + "" + port + "/" + schema + ""
                + "?autoReconnect=true"
                + "&useUnicode=true&characterEncoding=UTF-8"
                + (ssl ? "&verifyServerCertificate=false"
                + "&useSSL=true&requireSSL=true" : ""
                );
        this.USER = user;
        this.PASSWORD = password;
        this.TIMER.schedule(new TimerTask() {
            @Override
            public void run() {
                long idleTime = System.currentTimeMillis() - lastRelease;
                if (idleTime > MAX_IDLE_TIME) {
                    tryClose();
                }
            }
        }, 3000, 3000);
    }

    private void tryClose() {
        if (SEMAPHORE.tryAcquire()) {
            try {
                if (CONNECTION != null) {
                    try {
                        CONNECTION.close();
                        CONNECTION = null;
                        Server.logMySQL("connection closed.");
                    } catch (SQLException ex) {
                        Server.logError(ex);
                    }
                }
            } finally {
                SEMAPHORE.release();
            }
        }
    }

    private long lastRelease = System.currentTimeMillis();

    /**
     * Solicita uma conexão deste pooler.
     * @return uma conexão que pode ser nova ou reutilizada.
     */
    protected Connection acquire() {
        try {
            SEMAPHORE.acquire();
            if (CONNECTION == null) {
                Class.forName("com.mysql.jdbc.Driver");
                DriverManager.setLoginTimeout(3);
                CONNECTION = DriverManager.getConnection(URL, USER, PASSWORD);
                Server.logMySQL("connection created.");
            }
            CONNECTION.setAutoCommit(true);
            try (Statement statement = CONNECTION.createStatement()) {
                statement.executeUpdate("SET NAMES 'utf8mb4'");
            }
            CONNECTION.setAutoCommit(false);
            return CONNECTION;
        } catch (MySQLNonTransientConnectionException ex) {
            CONNECTION = null;
            Server.logMySQL("connection failed.");
            SEMAPHORE.release();
            return null;
        } catch (Exception ex) {
            Server.logError(ex);
            SEMAPHORE.release();
            return null;
        }
    }

    /**
     * Devolve uma conexão utilizada para este pooler.
     */
    protected void release() {
        lastRelease = System.currentTimeMillis();
        SEMAPHORE.release();
    }

    protected boolean close() {
        try {
            SEMAPHORE.acquire();
            if (CONNECTION != null) {
                CONNECTION.close();
                Server.logMySQL("connection closed.");
            }
            TIMER.cancel();
            return true;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
}
