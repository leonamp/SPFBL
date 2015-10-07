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
 * along with SPFBL.  If not, see <http://www.gnu.org/licenses/>.
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
