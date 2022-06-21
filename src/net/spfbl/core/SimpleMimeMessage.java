/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.spfbl.core;

import java.io.InputStream;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

/**
 *
 * @author leand
 */
public class SimpleMimeMessage extends MimeMessage {
    
    private String messageID = null;
    
    public SimpleMimeMessage(Session session, InputStream inputStream) throws MessagingException {
        super(session, inputStream);
        try {
            this.messageID = getHeader("Message-ID", null);
        } catch (MessagingException ex) {
            this.messageID = "<>";
            Server.logError(ex);
        }
    }
    
    public SimpleMimeMessage(MimeMessage message) throws MessagingException {
        super(message);
        try {
            this.messageID = message.getMessageID();
        } catch (MessagingException ex) {
            this.messageID = "<>";
            Server.logError(ex);
        }
    }
    
    @Override
    protected void updateMessageID() throws MessagingException {
        if (messageID == null) {
            super.updateMessageID();
            messageID = getMessageID();
        }
        setHeader("Message-ID", messageID);
    }
}
