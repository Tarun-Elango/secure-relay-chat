package com.udpholepunch;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
public class relay extends WebSocketServer {

    public static final int port = 8080;
    private final Gson gson = new Gson();
    private final SecureRandom secureRandom = new SecureRandom();

    private final String INVITE_TOKEN = generateId(); // printed once at startup
    private final int MAX_USERS = 5;
    private String adminId = null;

    // map clients
    private final Map<String, ClientInfo> clientInfos = new ConcurrentHashMap<>();
    private final Map<String, WebSocket> clients = new ConcurrentHashMap<>();

    private final Map<String, Long> lastMessageTime = new ConcurrentHashMap<>(); // used for rate limiting
    private static final long MIN_INTERVAL_MS = 200; // max 5 msg/sec

    public relay() {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        // Client connected, waiting for join message with credentials
    }
    @Override // this is where we handle incoming messages
    public void onMessage(WebSocket conn, String raw){
        if (raw.length() > 65_536) { // 64KB max
            safeSend(conn, "{\"type\":\"error\",\"msg\":\"Message too large\"}");
            return;
        }
        try{
            JsonObject msg = gson.fromJson(raw, JsonObject.class);
            String type = msg.get("type").getAsString();
            switch(type){
                case "join":
                    handleJoin(conn, msg);
                    break;
                case "message":
                    handleMessage(conn, msg);
                    break;
                default:
                    System.out.println("[-] Unknown message type: " + type);
            }
        }catch(Exception e){
            System.out.println("[-] Error processing message: " + e.getMessage());
        }
    }

    // this performs two main functions: when a new client joins, it sends them the current roster of clients, and then tells everyone else about the new client
    public void handleJoin(WebSocket conn, JsonObject msg){

        // 1. token check 
        String token = msg.has("token") ? msg.get("token").getAsString() : "";
        if (!token.equals(INVITE_TOKEN)) {
            safeSend(conn, "{\"type\":\"error\",\"msg\":\"Invalid invite token\"}");
            conn.close();
            return;
        }

        // 2. validate required fields
        if (!msg.has("publicKey") || msg.get("publicKey").getAsString().isBlank()) {
            safeSend(conn, "{\"type\":\"error\",\"msg\":\"Missing publicKey\"}");
            conn.close();
            return;
        }

        // 3. capacity check
        if (clients.size() >= MAX_USERS) {
            safeSend(conn, "{\"type\":\"error\",\"msg\":\"Server full\"}");
            conn.close();
            return;
        }
        
        String nickname = msg.has("nickname") ?
                msg.get("nickname").getAsString().replaceAll("[<> ]", "") : "Anonymous";
        if (nickname.length() > 32) {
            nickname = nickname.substring(0, 32);
        }
        String clientId = generateId();
        String publicKey = msg.get("publicKey").getAsString();

        // 4. First joiner becomes admin — synchronized to prevent race condition
        boolean isAdmin;
        synchronized (this) {
            isAdmin = (adminId == null);
            if (isAdmin) adminId = clientId;
        }

        ClientInfo info = new ClientInfo(clientId, nickname, publicKey);
        clients.put(clientId, conn); // key is clientId, value is WebSocket connection
        clientInfos.put(clientId, info); // store client info for later lookup

        // 1. Send roster to the new client
        JsonObject rosterMsg = new JsonObject();
        rosterMsg.addProperty("type", "roster");
        rosterMsg.addProperty("yourId", clientId);
        // 4. Include isAdmin in roster response
        rosterMsg.addProperty("isAdmin", isAdmin); // tells the joiner if THEY are admin
        
        JsonArray rooster = new JsonArray();
        for (String cid : clientInfos.keySet()){// for each client in the clientInfos map, if the id is not the same as the new client's id, add it to the roster
            if (!cid.equals(clientId)){
                ClientInfo c = clientInfos.get(cid);
                JsonObject peer = new JsonObject();
                peer.addProperty("id", c.id);
                peer.addProperty("nickname", c.nickname);
                peer.addProperty("publicKey", c.publicKey);
                // in the peer loop, also flag who is currently admin:
                peer.addProperty("isAdmin", cid.equals(adminId));
                rooster.add(peer);
            }
        }
        rosterMsg.add("clients", rooster);
        safeSend(conn, gson.toJson(rosterMsg));
        
        // 2. tell everyone else about the new client
        JsonObject joinMsg = new JsonObject();
        joinMsg.addProperty("type", "peer_joined");
        joinMsg.addProperty("id", clientId);
        joinMsg.addProperty("nickname", nickname);
        joinMsg.addProperty("publicKey", publicKey);
        // in peer_joined broadcast:
        joinMsg.addProperty("isAdmin", isAdmin);
        broadcastMsg(gson.toJson(joinMsg), conn); // convert the join message to JSON and

        System.out.println("[~] " + nickname + " (" + clientId + ") joined. Total: " + clients.size());
    }


    // this performs the core relay function — it takes an incoming message, identifies the sender, and then forwards it to the intended recipient(s)
    //  without ever looking at the plaintext content (the ciphertext and nonce are opaque values to the server)
    public void handleMessage(WebSocket conn, JsonObject msg){
        String senderId = null;

        // for each entry in the clients map, if the value (WebSocket) matches the connection, we found our sender's id
        for (Map.Entry<String, WebSocket> entry : clients.entrySet()) {
            if (entry.getValue() == conn) {
                senderId = entry.getKey();
                break;
            }
        }
        if (senderId == null) return;
        ClientInfo sender = clientInfos.get(senderId);
        if (sender == null) return;

        // validate required message fields
        if (!msg.has("ciphertext") || !msg.has("nonce")) return;

        // Rate limiting: if the sender has sent a message in the last MIN_INTERVAL_MS milliseconds, ignore this message to prevent spam
        long now = System.currentTimeMillis();
        long last = lastMessageTime.getOrDefault(senderId, 0L);
        if (now - last < MIN_INTERVAL_MS) return; // silently drop
        lastMessageTime.put(senderId, now);

        JsonObject payload = new JsonObject();
        payload.addProperty("type", "message");
        payload.addProperty("from", sender.id);
        payload.addProperty("fromNickname", sender.nickname);
        
        // Server just passes these opaque values along
        payload.add("ciphertext", msg.get("ciphertext")); 
        payload.add("nonce", msg.get("nonce"));
        payload.addProperty("timestamp", System.currentTimeMillis());

        String targetId = msg.has("to") ? msg.get("to").getAsString() : "all";
        payload.addProperty("to", targetId);

        // this is where the relay logic happens — if the message is for a specific client, send it there, otherwise broadcast to everyone
        if (!targetId.equals("all")) {
            WebSocket targetWs = clients.get(targetId);
            if (targetWs != null && targetWs.isOpen()) {
                safeSend(targetWs, gson.toJson(payload));
            }
        } else {
            broadcastMsg(gson.toJson(payload), conn);
        }

    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        String clientId = null;
        // for each entry in the clients map, if the value (WebSocket) matches the connection, we found our sender's id
        for (Map.Entry<String, WebSocket> entry : clients.entrySet()) {
            if (entry.getValue() == conn) {
                clientId = entry.getKey();
                break;
            }
        }
        if (clientId != null) {
            clients.remove(clientId);
            ClientInfo info = clientInfos.remove(clientId);
            lastMessageTime.remove(clientId); // clean up on disconnect
            if (info != null) {
                System.out.println("[-] Client disconnected: " + info.nickname + " (" + info.id + ")");

                // Notify others that this client has left
                JsonObject leaveMsg = new JsonObject();
                leaveMsg.addProperty("type", "peer_left");
                leaveMsg.addProperty("id", info.id);
                leaveMsg.addProperty("nickname", info.nickname);
                broadcastMsg(gson.toJson(leaveMsg), null);

                // Admin re-election: if admin left, assign to next available client
                synchronized (this) {
                    if (clientId.equals(adminId)) {
                        adminId = null;
                        if (!clientInfos.isEmpty()) {
                            String newAdminId = clientInfos.keySet().iterator().next(); // pick one id from the remaining clients
                            adminId = newAdminId;
                            ClientInfo newAdmin = clientInfos.get(newAdminId);
                            JsonObject adminMsg = new JsonObject();
                            adminMsg.addProperty("type", "new_admin");
                            adminMsg.addProperty("id", newAdminId);
                            adminMsg.addProperty("nickname", newAdmin.nickname);
                            broadcastMsg(gson.toJson(adminMsg), null); // send to everyone
                            System.out.println("[~] New admin: " + newAdmin.nickname + " (" + newAdminId + ")");
                        }
                    }
                }
            }
        } else {
            System.out.println("[-] Unknown client disconnected");
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        System.out.println("[-] Error occurred: " + ex.getMessage());
    }

    @Override
    public void onStart() {
        System.out.println("SecureChat relay running on port: " + getPort());
        System.out.println("Server is a dumb relay — it never sees plaintext messages.");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("INVITE TOKEN: " + INVITE_TOKEN);
        System.out.println("Max users: " + MAX_USERS);
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    // function to broadcast a message to all clients except the sender
    private void broadcastMsg(String text, WebSocket exclude) {
        for (WebSocket client : clients.values()) {
            if (client != exclude) {
                safeSend(client, text);
            }
        }
    }

    private void safeSend(WebSocket conn, String message) {
        try {
            conn.send(message);
        } catch (Exception e) {
            System.out.println("[-] Failed to send message: " + e.getMessage());
        }
    }

    private String generateId(){
        byte[] bytes = new byte[8];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){// for each byte, convert to hex and append to the string builder
            sb.append(String.format("%02x", b)); 
        }
        return sb.toString();
    }

    private static class ClientInfo{
        String id, nickname, publicKey;

            ClientInfo(String id, String nickname, String publicKey) {
                this.id = id;
                this.nickname = nickname;
                this.publicKey = publicKey;
            }
    }

    public static void main(String[] args) {
        relay server = new relay();
        server.start();
    }
}
