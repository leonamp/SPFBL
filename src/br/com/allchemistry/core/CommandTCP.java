/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * Servidor de commandos em TCP.
 * 
 * Este serviço responde o commando e finaliza a conexão logo em seguida.
 * 
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
 */
public final class CommandTCP extends Server {

    private final int PORT;
    private final ServerSocket SERVER_SOCKET;
    
    /**
     * Configuração e intanciamento do servidor para comandos.
     * @param port a porta TCP a ser vinculada.
     * @throws java.io.IOException se houver falha durante o bind.
     */
    public CommandTCP(int port) throws IOException {
        super("ServerCOMMAND");
        PORT = port;
        // Criando conexões.
        Server.logDebug("Binding command TCP socket on port " + port + "...");
        SERVER_SOCKET = new ServerSocket(port);
    }
    
    /**
     * Inicialização do serviço.
     */
    @Override
    public synchronized void run() {
        try {
            Server.logDebug("Listening commands on TCP port " + PORT + "...");
            while (continueListenning()) {
                try {
                    String command = null;
                    String result = null;
                    Socket socket = SERVER_SOCKET.accept();
                    try {
                        InputStream inputStream = socket.getInputStream();
                        InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "ISO-8859-1");
                        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                        command = bufferedReader.readLine();
                        if (command != null) {
                            result = CommandTCP.this.processCommand(command);
                            // Enviando resposta.
                            OutputStream outputStream = socket.getOutputStream();
                            outputStream.write(result.getBytes("ISO-8859-1"));
                            // Mede o tempo de resposta para estatísticas.
                        }
                    } finally {
                        // Fecha conexão logo após resposta.
                        socket.close();
                        // Log da consulta com o respectivo resultado.
                        Server.logCommand(socket.getInetAddress(), command, result);
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                    Server.logDebug("Command TCP listening stoped.");
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logDebug("Command TCP server closed.");
        }
    }
    
    @Override
    protected void close() throws Exception {
        Server.logDebug("Unbinding command TCP socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
