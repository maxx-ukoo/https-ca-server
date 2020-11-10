package ua.nat.maxx.hserver;

import io.netty.bootstrap.ServerBootstrap;

import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import ua.nat.maxx.hserver.cert.CertManager;
import ua.nat.maxx.hserver.cert.GeneratedCert;

import javax.net.ssl.SSLException;

/**
 * Discards any incoming data.
 */
public class DiscardServer {

    private final String hostName;
    private final int port;

    public DiscardServer(String hostName, int port) {
        this.port = port;
        this.hostName = hostName;
    }

    private SslContext buildSslContext() throws SSLException {
        CertManager certManager = new CertManager();
        GeneratedCert certificate = certManager.issueCertificate(hostName);

        return SslContextBuilder.forServer(certificate.privateKey, certificate.certificate).build();
    }

    public void run() throws Exception {
        EventLoopGroup bossGroup = new NioEventLoopGroup(); // (1)
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        SslContext cont = buildSslContext();

        try {
            ServerBootstrap b = new ServerBootstrap(); // (2)
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class) // (3)
                    .childHandler(new ChannelInitializer<SocketChannel>() { // (4)
                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {

                            //SelfSignedCertificate cert = new SelfSignedCertificate();
                            //SslContext cont = SslContext.newServerContext(cert.certificate(), cert.privateKey());
                            //SslContext cont2 = SslContextBuilder.forServer(cert.privateKey(), cert.certificate()).build();
                            //SSLEngine engine = cont2.newEngine(ch.alloc());
                            //engine.setUseClientMode(true);;
                            //cp.addFirst("ssl", new SslHandler(engine));
                            ch.pipeline().addFirst("ssl", cont.newHandler(ch.alloc()));
                            ch.pipeline().addLast(new DiscardServerHandler());
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)          // (5)
                    .childOption(ChannelOption.SO_KEEPALIVE, true); // (6)

            // Bind and start to accept incoming connections.
            ChannelFuture f = b.bind(port).sync(); // (7)

            // Wait until the server socket is closed.
            // In this example, this does not happen, but you can do that to gracefully
            // shut down your server.
            f.channel().closeFuture().sync();
        } finally {
            workerGroup.shutdownGracefully();
            bossGroup.shutdownGracefully();
        }
    }

}