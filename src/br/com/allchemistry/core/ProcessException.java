/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.core;

/**
 * Exceção de processamento.
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
@SuppressWarnings("serial")
public class ProcessException extends Exception {
    
    public ProcessException(String message) {
        super(message);
    }
    
    public ProcessException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getErrorMessage() {
        String message = getMessage();
        if (message.startsWith("ERROR: ")) {
            return message.substring(7);
        } else {
            return message;
        }
    }
}
