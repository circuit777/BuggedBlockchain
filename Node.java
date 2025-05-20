package tests;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/**
 * Node: локальный HTTP-сервер,
 * простой PoW-блокчейн,
 * постоянный кошелек,
 * вознаграждение с халвингом, параметры в genesis.
 */
public class Node {
    private static final String REGISTRY_URL = "http://185.22.234.182:5000/nodes";
    private static final String CHAIN_FILE = "blockchain.gz";
    private static final String PRIV_KEY_FILE = "private.key";
    private static final String PUB_KEY_FILE = "public.key";
    private static final int DIFFICULTY = 4;
    // Параметры эмиссии
    private static final int INITIAL_REWARD = 50;
    private static final int HALVING_INTERVAL = 100;
    private static final String INITIAL_ADDRESS = "f9d2e5b82a47edd1954ff2a25c4db6db6eb81c9c";
    private static final int INITIAL_AMOUNT = 100000;

    private final String myAddress;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final List<String> peers = Collections.synchronizedList(new ArrayList<>());
    private final List<Block> blockchain = Collections.synchronizedList(new ArrayList<>());

    // Wallet
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String walletAddress;

    static {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    public Node() throws Exception {
        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);

        KeyPair wallet = loadOrCreateWallet();
        privateKey = wallet.getPrivate();
        publicKey = wallet.getPublic();
        walletAddress = deriveAddress(publicKey);
        System.out.println("Wallet address: " + walletAddress);

        loadChain();

        String localIP = detectLocalIP();
        HttpServer server = HttpServer.create(new InetSocketAddress(localIP, 0), 0);
        int port = server.getAddress().getPort();
        myAddress = localIP + ":" + port;

        server.createContext("/nodes", new NodesHandler());
        server.createContext("/chain", new ChainHandler());
        server.createContext("/add", new AddHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Server at " + myAddress);

        startSync();
    }

    private KeyPair loadOrCreateWallet() throws Exception {
        Path privPath = Path.of(PRIV_KEY_FILE);
        Path pubPath = Path.of(PUB_KEY_FILE);
        if (Files.exists(privPath) && Files.exists(pubPath)) {
            try {
                // Read keys from PEM files
                String privPem = Files.readString(privPath);
                String pubPem = Files.readString(pubPath);

                // Remove PEM headers and decode Base64
                String privBase64 = privPem.replace("-----BEGIN PRIVATE KEY-----\n", "")
                        .replace("\n-----END PRIVATE KEY-----\n", "")
                        .replaceAll("\\s", "");
                String pubBase64 = pubPem.replace("-----BEGIN PUBLIC KEY-----\n", "")
                        .replace("\n-----END PUBLIC KEY-----\n", "")
                        .replaceAll("\\s", "");

                byte[] privBytes = Base64.getDecoder().decode(privBase64);
                byte[] pubBytes = Base64.getDecoder().decode(pubBase64);

                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
                return new KeyPair(kf.generatePublic(pubSpec), kf.generatePrivate(privSpec));
            } catch (Exception e) {
                System.err.println("Error loading wallet: " + e.getMessage());
                throw e;
            }
        }

        // Generate new ECDSA key pair with secp256k1
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        kpg.initialize(ecSpec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        // Save keys in PEM format
        byte[] privBytes = kp.getPrivate().getEncoded();
        byte[] pubBytes = kp.getPublic().getEncoded();

        // Encode to Base64 and add PEM headers
        String privPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privBytes) +
                "\n-----END PRIVATE KEY-----\n";
        String pubPem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(pubBytes) +
                "\n-----END PUBLIC KEY-----\n";

        // Save to files
        try {
            Files.writeString(privPath, privPem);
            Files.writeString(pubPath, pubPem);
        } catch (IOException e) {
            System.err.println("Error saving wallet: " + e.getMessage());
            throw e;
        }

        return kp;
    }

    private String deriveAddress(PublicKey pubKey) throws Exception {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(pubKey.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 20; i++) sb.append(String.format("%02x", hash[i]));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error deriving address: " + e.getMessage());
            throw e;
        }
    }

    private void loadChain() {
        File file = new File(CHAIN_FILE);
        if (file.exists()) {
            try (GZIPInputStream gis = new GZIPInputStream(new FileInputStream(file));
                 Reader isr = new InputStreamReader(gis, StandardCharsets.UTF_8);
                 BufferedReader br = new BufferedReader(isr)) {
                List<Block> loaded = objectMapper.readValue(br, new TypeReference<>() {});
                if (isValidChain(loaded)) {
                    synchronized (blockchain) {
                        blockchain.clear();
                        blockchain.addAll(loaded);
                    }
                    System.out.println("Loaded chain length: " + blockchain.size());
                    // Проверка содержимого генезис-блока
                    JsonNode genesisData = objectMapper.readTree(blockchain.get(0).data);
                    System.out.println("Genesis config: " + genesisData.toString());
                    return;
                } else {
                    System.err.println("Loaded chain is invalid, creating new genesis block");
                }
            } catch (IOException e) {
                System.err.println("Error loading chain: " + e.getMessage());
            }
        }
        // Create genesis block
        synchronized (blockchain) {
            blockchain.clear();
            blockchain.add(Block.createGenesis());
        }
        saveChain();
    }

    private void saveChain() {
        try (GZIPOutputStream gos = new GZIPOutputStream(new FileOutputStream(CHAIN_FILE));
             Writer osw = new OutputStreamWriter(gos, StandardCharsets.UTF_8);
             BufferedWriter bw = new BufferedWriter(osw)) {
            synchronized (blockchain) {
                objectMapper.writeValue(bw, blockchain);
            }
            System.out.println("Saved chain length: " + blockchain.size());
        } catch (IOException e) {
            System.err.println("Error saving chain: " + e.getMessage());
        }
    }

    private String detectLocalIP() throws SocketException {
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!ni.isUp() || ni.isLoopback()) continue;
            for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                if (addr instanceof Inet4Address) return addr.getHostAddress();
            }
        }
        System.err.println("No suitable network interface found, using localhost");
        return "127.0.0.1";
    }

    private class NodesHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            ObjectNode root = objectMapper.createObjectNode();
            synchronized (peers) {
                root.putPOJO("nodes", peers);
            }
            byte[] resp = objectMapper.writeValueAsBytes(root);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, resp.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(resp);
            }
        }
    }

    private class ChainHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            byte[] resp;
            synchronized (blockchain) {
                resp = objectMapper.writeValueAsBytes(blockchain);
            }
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, resp.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(resp);
            }
        }
    }

    private class AddHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            try {
                JsonNode req = objectMapper.readTree(ex.getRequestBody());
                String userData = req.has("data") ? req.get("data").asText() : "";
                synchronized (blockchain) {
                    Block last = blockchain.get(blockchain.size() - 1);
                    // Read parameters from genesis
                    JsonNode cfg = objectMapper.readTree(blockchain.get(0).data);
                    int initR = cfg.get("initialReward").asInt();
                    int interval = cfg.get("halvingInterval").asInt();
                    int height = last.index + 1;
                    int halvings = height / interval;
                    int rewardAmt = initR >> halvings;

                    ObjectNode dataNode = objectMapper.createObjectNode();
                    dataNode.put("data", userData);
                    ObjectNode rewardNode = objectMapper.createObjectNode();
                    rewardNode.put("to", walletAddress);
                    rewardNode.put("amount", rewardAmt);
                    dataNode.set("reward", rewardNode);
                    String blockData = objectMapper.writeValueAsString(dataNode);

                    Block newBlock = new Block(height, Instant.now().toEpochMilli(), blockData, last.hash);
                    newBlock.mineBlock(DIFFICULTY);
                    blockchain.add(newBlock);
                    saveChain();
                    byte[] resp = objectMapper.writeValueAsBytes(newBlock);
                    ex.getResponseHeaders().add("Content-Type", "application/json");
                    ex.sendResponseHeaders(201, resp.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(resp);
                    }
                }
            } catch (Exception e) {
                System.err.println("Error processing add request: " + e.getMessage());
                ex.sendResponseHeaders(400, -1);
            }
        }
    }

    private void startSync() {
        ScheduledExecutorService sch = Executors.newSingleThreadScheduledExecutor();
        sch.scheduleAtFixedRate(() -> {
            syncPeers();
            syncChain();
        }, 0, 1, TimeUnit.MINUTES);
    }

    private void syncPeers() {
        try {
            String url = REGISTRY_URL + "?address=" + URLEncoder.encode(myAddress, StandardCharsets.UTF_8);
            HttpResponse<String> r = httpClient.send(
                    HttpRequest.newBuilder().uri(URI.create(url)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() == 200) {
                JsonNode j = objectMapper.readTree(r.body());
                List<String> up = objectMapper.convertValue(j.get("nodes"), new TypeReference<>() {});
                synchronized (peers) {
                    peers.clear();
                    peers.addAll(up);
                }
                System.out.println("Synced peers: " + peers.size());
            }
        } catch (Exception e) {
            System.err.println("Peers sync error: " + e.getMessage());
        }
    }

    private void syncChain() {
        List<List<Block>> chains = new ArrayList<>();
        synchronized (blockchain) {
            chains.add(new ArrayList<>(blockchain));
        }
        synchronized (peers) {
            for (String peer : peers) {
                if (peer.equals(myAddress)) continue;
                try {
                    String url = "http://" + peer + "/chain";
                    HttpResponse<String> r = httpClient.send(
                            HttpRequest.newBuilder().uri(URI.create(url)).GET().build(),
                            HttpResponse.BodyHandlers.ofString());
                    if (r.statusCode() == 200) {
                        List<Block> c = objectMapper.readValue(r.body(), new TypeReference<>() {});
                        chains.add(c);
                    }
                } catch (Exception e) {
                    System.err.println("Error syncing chain from " + peer + ": " + e.getMessage());
                }
            }
        }
        List<Block> best = null;
        for (List<Block> c : chains) {
            if (isValidChain(c) && (best == null || c.size() > best.size())) {
                best = c;
            }
        }
        if (best == null) {
            best = new ArrayList<>();
            best.add(Block.createGenesis());
        }
        synchronized (blockchain) {
            blockchain.clear();
            blockchain.addAll(best);
            saveChain();
            System.out.println("Synced chain length: " + blockchain.size());
            // Проверка содержимого генезис-блока
            try {
                JsonNode genesisData = objectMapper.readTree(blockchain.get(0).data);
                System.out.println("Synced genesis config: " + genesisData.toString());
            } catch (IOException e) {
                System.err.println("Error reading synced genesis data: " + e.getMessage());
            }
        }
    }

    private boolean isValidChain(List<Block> chain) {
        if (chain.isEmpty()) {
            System.err.println("Chain validation failed: chain is empty");
            return false;
        }
        Block g = Block.createGenesis();
        if (chain.get(0).index != g.index || !chain.get(0).hash.equals(g.hash)) {
            System.err.println("Chain validation failed: invalid genesis block");
            return false;
        }
        for (int i = 1; i < chain.size(); i++) {
            Block p = chain.get(i - 1);
            Block c = chain.get(i);
            if (!c.previousHash.equals(p.hash) || !c.calculateHash().equals(c.hash)) {
                System.err.println("Chain validation failed at block " + i);
                return false;
            }
        }
        return true;
    }

    public static class Block {
        public int index;
        public long timestamp;
        public String data;
        public String previousHash;
        public long nonce;
        public String hash;

        public Block() {}

        public Block(int index, long timestamp, String data, String previousHash) {
            this.index = index;
            this.timestamp = timestamp;
            this.data = data;
            this.previousHash = previousHash;
            this.nonce = 0;
            this.hash = calculateHash();
        }

        public String calculateHash() {
            try {
                String txt = index + Long.toString(timestamp) + data + previousHash + nonce;
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] d = md.digest(txt.getBytes(StandardCharsets.UTF_8));
                Formatter f = new Formatter();
                for (byte b : d) f.format("%02x", b);
                String res = f.toString();
                f.close();
                return res;
            } catch (Exception e) {
                throw new RuntimeException("Error calculating hash: " + e.getMessage(), e);
            }
        }

        public void mineBlock(int difficulty) {
            String prefix = new String(new char[difficulty]).replace('\0', '0');
            while (!hash.substring(0, difficulty).equals(prefix)) {
                nonce++;
                hash = calculateHash();
            }
        }

        public static Block createGenesis() {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode configNode = mapper.createObjectNode();
            configNode.put("initialReward", INITIAL_REWARD);
            configNode.put("halvingInterval", HALVING_INTERVAL);
            ObjectNode allocationNode = mapper.createObjectNode();
            allocationNode.put("to", INITIAL_ADDRESS);
            allocationNode.put("amount", INITIAL_AMOUNT);
            configNode.set("initialAllocation", allocationNode);
            String configJson;
            try {
                configJson = mapper.writeValueAsString(configNode);
            } catch (IOException e) {
                throw new RuntimeException("Error serializing genesis config", e);
            }
            Block g = new Block(0, Instant.EPOCH.toEpochMilli(), configJson, "0");
            g.mineBlock(DIFFICULTY);
            return g;
        }
    }

    public static void main(String[] args) throws Exception {
        new Node();
    }
}