/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.core;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * Programa cliente para teste de consulta em UDP.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Client {

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception se houver falha.
     */
    public static void main(String[] args) throws Exception {
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        DatagramSocket clientSocket = new DatagramSocket();
        try {
            boolean run = true;
            while (run) {
                InetAddress ipAddress = InetAddress.getByName("localhost");
                String sentence = inFromUser.readLine();
                byte[] sendData = sentence.getBytes();
                DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, ipAddress, 9876);
                clientSocket.send(sendPacket);
                byte[] receiveData = new byte[1024];
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                clientSocket.receive(receivePacket);
                String response = new String(receivePacket.getData()).trim();
                System.out.println(response);
                if (sentence.equals("QUIT")) {
                    run = false;
                } else if (sentence.equals("SHUTDOWN") && response.equals("OK")) {
                    run = false;
                }
            }
        } finally {
            clientSocket.close();
        }
        
    }
}
