package com.hubspot.smtp;

import static io.netty.handler.codec.smtp.SmtpCommand.DATA;
import static io.netty.handler.codec.smtp.SmtpCommand.EHLO;
import static io.netty.handler.codec.smtp.SmtpCommand.MAIL;
import static io.netty.handler.codec.smtp.SmtpCommand.QUIT;
import static io.netty.handler.codec.smtp.SmtpCommand.RCPT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.Lists;
import com.google.common.io.CharStreams;
import com.hubspot.smtp.client.EhloResponse;
import com.hubspot.smtp.client.Extension;
import com.hubspot.smtp.client.SmtpClientResponse;
import com.hubspot.smtp.client.SmtpSession;
import com.hubspot.smtp.client.SmtpSessionConfig;
import com.hubspot.smtp.client.SmtpSessionFactory;
import com.hubspot.smtp.client.SmtpSessionFactoryConfig;
import com.hubspot.smtp.messages.MessageContent;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.smtp.DefaultSmtpRequest;
import io.netty.handler.codec.smtp.SmtpCommand;
import io.netty.handler.codec.smtp.SmtpRequest;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import org.apache.james.protocols.api.Encryption;
import org.apache.james.protocols.api.logger.Logger;
import org.apache.james.protocols.netty.NettyServer;
import org.apache.james.protocols.smtp.MailEnvelope;
import org.apache.james.protocols.smtp.SMTPConfigurationImpl;
import org.apache.james.protocols.smtp.SMTPProtocol;
import org.apache.james.protocols.smtp.SMTPProtocolHandlerChain;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.hook.AuthHook;
import org.apache.james.protocols.smtp.hook.HookResult;
import org.apache.james.protocols.smtp.hook.MailParametersHook;
import org.apache.james.protocols.smtp.hook.MessageHook;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import javax.net.ssl.SSLEngine;

/**
 * EmailSendTest class for send email with basic requirements
 */
public class EmailSendTest {
    private static final long MAX_MESSAGE_SIZE = 1234000L;

    // host of SMTP mail server
    private static final String MailServerHost = "mail.qq.com";

    // user and passwd
    private static final String USERNAME = "smtp-user";

    // password of user
    private static final String PASSWORD = "correct horse battery staple";

    private static final String RETURN_PATH = "allen@qq.com";

    private static final String RECIPIENT = "allen@qq.com";

    /**
     * 邮件签名分隔符
     */
    private static final String SIGNATURE_SEPARATE_PNG = "________________________";

    /**
     * 邮件签名分隔符html
     */
    private static final String SIGNATURE_SEPARATE_PNG_HTML = "<br/><br/><br/>________________________<br/><br/>";

    // 网页的html格式
    private static String html = new StringBuilder()
        // .append("<!doctype  html>\n")
        .append("<html>\n")
        .append("<head>\n")
        .append("	<title>这是一个网页</title>\n")
        .append("</head>\n")
        .append("<body>\n")
        .append("   <table  border=3  width=\"200\"  height=\"100\"  bordercolor=\"red\">\n")
        .append("   <caption>电话号码</caption>\n")
        .append("	<tr>\n")
        .append("	  <td>急救:</td>\n")
        .append("	  <td>110</td>\n")
        .append("	</tr>\n")
        .append("	<tr>\n")
        .append("	  <td>火警:</td>\n")
        .append("	  <td>119</td>\n")
        .append("	</tr>\n")
        .append("	</tr>\n")
        .append("	</table>\n")
        .append("</body>\n")
        .append("</html>")
        .toString();

    private static final String MESSAGE_DATA = ""
        + "From: allen <allen@qq.com>\r\n"
        + "To: wcs3000 <wcs3000@qq.com>\r\n"
        + "Cc: allen <allen@qq.com>, zhangke <zhangke3000@qq.com>\r\n"
        + "BCC: zhuqixin <zhuqixin3000@qq.com>, shimin <shimin3000@qq.com>\r\n"
        + "Subject: test mail\r\n"
        + "Date: Fri, 8 Jan 2020 16:12:30\r\n"
        + "Mime-Version: 1.0\r\n"
        + "Content-type: multipart/mixed;boundary=\"abc\"\r\n"

        // 邮件正文, charset
        + "\r\n"
        + "--abc\r\n"
        + "Content-Type: text/plain; charset=UTF-8\r\n"
        + "Content-Transfer-Encoding: quoted-printable\r\n"
        // 正文内容
        + "\r\n"
        + "Hello everyone, this is a test email form allen.\r\n"
        + "Hello everyone, this is a test email form allen."
        // 签名, java mail提供, html则为 <br>
        + SIGNATURE_SEPARATE_PNG_HTML
        + "allen\r\n"
        + "allen@qq.com\r\n"
        + "better code better world!\r\n"

        + "\r\n"
        // 邮件附件, Content-Type 内容类型, 内容传输编码方式base64
        + "--abc\r\n"
        // + "Content-Type: application/octet-stream; name=a.txt\r\n"
        + "Content-Disposition: attachment; filename=a.txt\r\n"
        + "Content-Transfer-Encoding: base64\r\n"
        // 附件内容
        + "\r\n"
        + "Y29ycmVjdCBob3JzZSBiYXR0ZXJ5IHN0YXBsZQ=="
        + "\r\n"

        // 多个附件
        + "--abc\r\n"
        // + "Content-Type: application/octet-stream; name=b.txt\r\n"
        + "Content-Disposition: attachment; filename=b.txt\r\n"
        + "Content-Transfer-Encoding: base64\r\n"
        // 附件内容
        + "\r\n"
        + "dGhpcyBpcyBjb250ZW50IGZvciBmaWxlIGI="
        + "\r\n"

        // 最终结束
        + "--abc--\r\n";

    private static final String MESSAGE_HTML_DATA = ""
        + "From: allen <allen@qq.com>\r\n"
        + "To: wcs3000 <wcs3000@qq.com>\r\n"
        + "Cc: allen <allen@qq.com>, zhangke <zhangke3000@qq.com>\r\n"
        + "BCC: zhuqixin <zhuqixin3000@qq.com>, shimin <shimin3000@qq.com>\r\n"
        + "Subject: test mail\r\n"
        + "Date: Fri, 8 Jan 2020 16:12:30\r\n"
        + "Mime-Version: 1.0\r\n"
        + "Content-type: multipart/mixed;boundary=\"abc\"\r\n"

        // 邮件正文, charset, html 也可以以base64编码
        + "\r\n"
        + "--abc\r\n"
        + "Content-Type: text/html; charset=UTF-8\r\n"
        + "Content-Transfer-Encoding: 8bit\r\n"
        // 正文内容 (html格式)
        + "\r\n"
        + html
        // 签名, java mail提供, html则为 <br>
        + "<br/>"
        + "<br/>"
        + "<br/>"
        + SIGNATURE_SEPARATE_PNG
        + "<br/"
        + "<br/>"
        + "allen<br/>"
        + "allen@qq.com<br/>"
        + "better code better world!<br/>"

        + "\r\n"
        // 邮件附件, Content-Type 内容类型, 内容传输编码方式base64
        + "--abc\r\n"
        // + "Content-Type: application/octet-stream; name=a.txt\r\n"
        + "Content-Disposition: attachment; filename=a.txt\r\n"
        + "Content-Transfer-Encoding: base64\r\n"
        // 附件内容
        + "\r\n"
        + "Y29ycmVjdCBob3JzZSBiYXR0ZXJ5IHN0YXBsZQ=="
        + "\r\n"

        // 多个附件
        + "--abc\r\n"
        // + "Content-Type: application/octet-stream; name=b.txt\r\n"
        + "Content-Disposition: attachment; filename=b.txt\r\n"
        + "Content-Transfer-Encoding: base64\r\n"
        // 附件内容
        + "\r\n"
        + "dGhpcyBpcyBjb250ZW50IGZvciBmaWxlIGI="
        + "\r\n"

        // 最终结束
        + "--abc--\r\n";

    private static final NioEventLoopGroup EVENT_LOOP_GROUP = new NioEventLoopGroup();

    private InetSocketAddress serverAddress;

    private NettyServer smtpServer;

    private SmtpSessionFactory sessionFactory;

    private List<MailEnvelope> receivedMails;

    private String receivedMessageSize;

    private Logger serverLog;

    private boolean requireAuth;



    @Before
    public void setup() throws Exception {
        receivedMails = Lists.newArrayList();
        serverAddress = new InetSocketAddress(getFreePort());
        serverLog = mock(Logger.class);
        smtpServer = createAndStartSmtpServer(serverLog, serverAddress);
        // .withSslEngineSupplier(this::createInsecureSSLEngine)
        sessionFactory = new SmtpSessionFactory(SmtpSessionFactoryConfig.nonProductionConfig());

        when(serverLog.isDebugEnabled()).thenReturn(true);
    }

    private NettyServer createAndStartSmtpServer(Logger log, InetSocketAddress address) throws Exception {
        SMTPConfigurationImpl config = new SMTPConfigurationImpl() {
            @Override
            public boolean isAuthRequired(String remoteIP) {
                return requireAuth;
            }

            @Override
            public long getMaxMessageSize() {
                return MAX_MESSAGE_SIZE;
            }
        };

        SMTPProtocolHandlerChain chain = new SMTPProtocolHandlerChain(new CollectEmailsHook(), new ChunkingExtension());
        SMTPProtocol protocol = new SMTPProtocol(chain, config, log);
        Encryption encryption = Encryption.createStartTls(FakeTlsContext.createContext());

        NettyServer server = new ExtensibleNettyServer(protocol, encryption);
        server.setListenAddresses(address);
        server.bind();

        return server;
    }

    @After
    public void after() {
        smtpServer.unbind();
    }

    @Test
    public void itCanSendAnEmail() throws Exception {
        connect().thenCompose(r -> assertSuccess(r).send(req(EHLO, MailServerHost)))
            .thenCompose(r -> {
                EhloResponse ehloResponse = r.getSession().getEhloResponse();
                assertThat(r.getSession().getEhloResponse().isSupported(Extension.AUTH)).isTrue();
                assertThat(r.getSession().getEhloResponse().isAuthLoginSupported()).isTrue();
                return r.getSession().authLogin(USERNAME, PASSWORD);
            })
            // .thenCompose(r -> assertSuccess(r).send(req(MAIL, "FROM:<" + "allen@qq.com" + ">", "SIZE=" + MESSAGE_DATA.length())))
            .thenCompose(r -> assertSuccess(r).send(req(MAIL, "FROM:<" + "allen@qq.com" + ">")))
            .thenCompose(r -> assertSuccess(r).send(req(RCPT, "TO:<" + "allen@qq.com" + ">")))
            //.thenCompose(r -> assertSuccess(r).send(req(RCPT, "TO:<" + "zhuqixin3000@qq.com" + ">")))
            //.thenCompose(r -> assertSuccess(r).send(req(RCPT, "TO:<" + "wcs3000@qq.com" + ">")))
            //.thenCompose(r -> assertSuccess(r).send(req(RCPT, "TO:<" + "shimin3000@qq.com" + ">")))
            .thenCompose(r -> assertSuccess(r).send(req(DATA)))
            .thenCompose(r -> assertSuccess(r).send(createMessageContent()))
            .thenCompose(r -> assertSuccess(r).send(req(QUIT)))
            .thenCompose(r -> assertSuccess(r).close())
            .get();

        assertThat(receivedMails.size()).isEqualTo(1);
        MailEnvelope mail = receivedMails.get(0);

        assertThat(mail.getSender().toString()).isEqualTo(RETURN_PATH);
        assertThat(mail.getRecipients().get(0).toString()).isEqualTo(RECIPIENT);
        assertThat(readContents(mail)).contains(MESSAGE_DATA);
        assertThat(receivedMessageSize).contains(Integer.toString(MESSAGE_DATA.length()));
    }

    @Test
    public void itCanSendEmailsWithMultipleRecipients() throws Exception {
        connect(getDefaultConfig().withDisabledExtensions(EnumSet.of(Extension.CHUNKING))).thenCompose(
            r -> assertSuccess(r).send(req(EHLO, "hubspot.com")))
            .thenCompose(r -> assertSuccess(r).send(RETURN_PATH, Lists.newArrayList("a@example.com", "b@example.com"),
                createMessageContent()))
            .thenCompose(r -> assertSuccess(r).send(req(QUIT)))
            .thenCompose(r -> assertSuccess(r).close())
            .get();

        assertThat(receivedMails.size()).isEqualTo(1);
        MailEnvelope mail = receivedMails.get(0);

        assertThat(mail.getSender().toString()).isEqualTo(RETURN_PATH);
        assertThat(mail.getRecipients().get(0).toString()).isEqualTo("a@example.com");
        assertThat(mail.getRecipients().get(1).toString()).isEqualTo("b@example.com");
        assertThat(readContents(mail)).contains(MESSAGE_DATA);
    }

    private String repeat(String s, int n) {
        return new String(new char[n]).replace("\0", s);
    }

    private String readContents(MailEnvelope mail) throws IOException {
        return CharStreams.toString(new InputStreamReader(mail.getMessageInputStream()));
    }

    private SmtpSession assertSuccess(SmtpClientResponse r) {
        assertThat(r.containsError()).withFailMessage("Received error: " + r).isFalse();
        return r.getSession();
    }

    private CompletableFuture<SmtpClientResponse> connect() {
        return connect(getDefaultConfig());
    }

    private SmtpSessionConfig getDefaultConfig() {
        // 自定义邮箱服务器地址
        return SmtpSessionConfig.forRemoteAddress(MailServerHost, MailServerPort);
        // return SmtpSessionConfig.forRemoteAddress(serverAddress);
    }

    private SSLEngine createInsecureSSLEngine() {
        try {
            return SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build()
                .newEngine(PooledByteBufAllocator.DEFAULT);
        } catch (Exception e) {
            throw new RuntimeException("Could not create SSLEngine", e);
        }
    }

    private CompletableFuture<SmtpClientResponse> connect(SmtpSessionConfig config) {
        return sessionFactory.connect(config);
    }

    private static SmtpRequest req(SmtpCommand command, CharSequence... arguments) {
        return new DefaultSmtpRequest(command, arguments);
    }

    private synchronized static int getFreePort() {
        for (int port = 20000; port <= 30000; port++) {
            try {
                ServerSocket socket = new ServerSocket(port);
                socket.setReuseAddress(true);
                socket.close();
                return port;
            } catch (IOException ignored) {
                // ignore
            }
        }

        throw new RuntimeException("Could not find a port to listen on");
    }

    private MessageContent createMessageContent() {
        return MessageContent.of(createBuffer(MESSAGE_DATA));
    }

    private ByteBuf createBuffer(String s) {
        return Unpooled.wrappedBuffer(s.getBytes(StandardCharsets.UTF_8));
    }

    private class CollectEmailsHook implements MessageHook, MailParametersHook, AuthHook {
        @Override
        public synchronized HookResult onMessage(SMTPSession session, MailEnvelope mail) {
            receivedMails.add(mail);
            return HookResult.ok();
        }

        @Override
        public HookResult doAuth(SMTPSession session, String username, String password) {
            if (username.equals(USERNAME) && password.equals(PASSWORD)) {
                return HookResult.ok();
            } else {
                return HookResult.deny();
            }
        }

        @Override
        public HookResult doMailParameter(SMTPSession session, String paramName, String paramValue) {
            if (paramName.equalsIgnoreCase("size")) {
                receivedMessageSize = paramValue;
            }

            return null;
        }

        @Override
        public String[] getMailParamNames() {
            return new String[] {"SIZE"};
        }
    }
}
