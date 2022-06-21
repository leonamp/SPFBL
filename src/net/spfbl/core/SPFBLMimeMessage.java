/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.spfbl.core;

import javax.mail.Address;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 *
 * @author leand
 */
public class SPFBLMimeMessage extends MimeMessage {
    
    public SPFBLMimeMessage(Session session) {
        super(session);
    }
    
    public SPFBLMimeMessage(MimeMessage message) throws MessagingException {
        super(message);
    }
    
    public InternetAddress getFromInternetAddress() {
        try {
            Address[] fromArray = getFrom();
            if (fromArray == null) {
                return null;
            } else if (fromArray.length == 0) {
                return null;
            } else if (fromArray[0] instanceof InternetAddress) {
                return (InternetAddress) fromArray[0];
            } else {
                return null;
            }
        } catch (MessagingException ex) {
            return null;
        }
    }
    
    public String getFromAddress() {
        InternetAddress from = getFromInternetAddress();
        if (from == null) {
            return "";
        } else {
            return from.getAddress();
        }
    }
    
    private String getHostname() {
        String hostname = Core.getHostname();
        if (hostname == null) {
            return "localhost";
        } else {
            return hostname;
        }
    }
    
    @Override
    protected void updateMessageID() throws MessagingException {
        try {
            long time = Server.getNewUniqueTime();
            String from = getFromAddress();
            String ticket = Core.encryptURL(time, from);
            String hostname = getHostname();
            String messageID = '<' + ticket + '@' + hostname + '>';
            setHeader("Message-ID", messageID);
        } catch (ProcessException ex) {
            Server.logError(ex);
            super.updateMessageID();
        }
    }
}
