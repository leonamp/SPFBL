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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedList;
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
    private final int MAX_CONNECTIONS = 3;
    private final Semaphore SEMAPHORE = new Semaphore(1);
    private final LinkedList<Connection> QUEUE = new LinkedList<Connection>();
    
    private int polledCount = 0;

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
                try {
                    long idleTime = System.currentTimeMillis() - lastPoll;
                    if (idleTime > MAX_IDLE_TIME || QUEUE.size() > 1) {
                        closeLastConnection();
                    }
                } catch (SQLException ex) {
                    Server.logError(ex);
                }
            }
        }, 3000, 3000);
    }

    private void closeLastConnection() throws SQLException {
        if (SEMAPHORE.tryAcquire()) {
            try {
                if (!QUEUE.isEmpty()) {
                    Connection connection = QUEUE.poll();
                    connection.close();
                    Server.logMySQL("connection closed.");
                }
            } finally {
                SEMAPHORE.release();
            }
        }
    }

    private long lastPoll = System.currentTimeMillis();

    /**
     * Solicita uma conexão deste pooler.
     * @return uma conexão que pode ser nova ou reutilizada.
     * @throws SQLException se houver exceção nas operações com o banco de dados.
     * @throws ClassNotFoundException se a bibioteca de conexão MySQL não for encontrada.
     */
    protected Connection pollConnection() throws SQLException, ClassNotFoundException {
        try {
            SEMAPHORE.acquire();
            try {
                Connection connection = QUEUE.poll();
                if (connection == null) {
                    Class.forName("com.mysql.jdbc.Driver");
                    DriverManager.setLoginTimeout(3);
                    connection = DriverManager.getConnection(URL, USER, PASSWORD);
                    Server.logMySQL("connection created.");
                }
                try {
                    connection.setAutoCommit(true);
                    Statement statement = connection.createStatement();
                    try {
                        statement.executeUpdate("SET NAMES 'utf8mb4'");
                    } finally {
                        statement.close();
                    }
                    connection.setAutoCommit(false);
                    polledCount++;
                    lastPoll = System.currentTimeMillis();
                    Server.logMySQL("connection catched.");
                    return connection;
                } catch (SQLException ex) {
                    connection.rollback();
                    QUEUE.offer(connection);
                    throw ex;
                }
            } finally {
                SEMAPHORE.release();
            }
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return null;
        }
    }

    /**
     * Devolve uma conexão utilizada para este pooler.
     * @param connection a conexão que não será mais utilizada pelo solicitante.
     * @return verdadeiro se a oferta foi bem sucedida.
     * @throws SQLException se houver falha no procedimento.
     */
    protected boolean offerConnection(Connection connection) throws SQLException {
        try {
            SEMAPHORE.acquire();
            try {
                try {
                    polledCount--;
                    Server.logMySQL("connection returned.");
                    connection.rollback();
                    lastPoll = System.currentTimeMillis();
                    return true;
                } finally {
                    if (QUEUE.size() >= MAX_CONNECTIONS) {
                        connection.close();
                    } else {
                        QUEUE.offer(connection);
                    }
                }
            } finally {
                SEMAPHORE.release();
            }
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return false;
        }
    }

    protected boolean close() throws SQLException {
        if (SEMAPHORE.tryAcquire() && polledCount == 0) {
            while (!QUEUE.isEmpty()) {
                Connection connection = QUEUE.poll();
                connection.close();
                Server.logMySQL("connection closed.");
            }
            TIMER.cancel();
            return true;
        } else {
            return false;
        }
    }
}
