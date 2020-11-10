package ua.nat.maxx.hserver;

public class Starter {

    public static void main(String[] args) throws Exception {
        DiscardServer server = new DiscardServer("apps.enernoc.com", 443);
        server.run();
    }
}
