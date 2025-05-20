package tests;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Verifies signatures for user transactions in a compressed blockchain file with detailed logging.
 * Skips reward transactions and verifies signatures against JSON-encoded transaction data.
 */
public class BlockchainSignatureVerifier {
    private static final String CHAIN_FILE = "blockchain.gz";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Verifies ECDSA signatures for user transactions in the blockchain's 'data' field.
     * Expects 'data' to contain a JSON string with a single transaction object including:
     * - from: sender address
     * - to: recipient address
     * - amount: transaction amount
     * - signature: Base64-encoded ECDSA signature
     * - pubkey: Base64-encoded public key in DER format
     */
    public static void verifyBlockchainSignatures() {
        System.out.println("Blockchain Signature Verifier started at " + new java.util.Date());
        System.out.println("Starting blockchain signature verification...");
        System.out.println("Loading blockchain from file: " + CHAIN_FILE);

        try {
            // Load blockchain from compressed file
            List<Node.Block> blockchain = loadBlockchain();
            System.out.println("Loaded blockchain with " + blockchain.size() + " blocks");

            int totalTransactions = 0;
            int validSignatures = 0;
            int invalidSignatures = 0;

            // Iterate through each block
            for (Node.Block block : blockchain) {
                System.out.println("\nVerifying block #" + block.index + " (hash: " + block.hash + ")");
                System.out.println("Block timestamp: " + new java.util.Date(block.timestamp));
                System.out.println("Block previousHash: " + block.previousHash);
                System.out.println("Block nonce: " + block.nonce);
                System.out.println("Block data (raw): " + block.data);

                // Parse block data as JSON
                JsonNode blockData;
                try {
                    blockData = objectMapper.readTree(block.data);
                    System.out.println("Parsed block data JSON: " + blockData.toPrettyString());
                } catch (IOException e) {
                    System.err.println("Error parsing block data as JSON for block #" + block.index + ": " + e.getMessage());
                    e.printStackTrace();
                    continue;
                }

                // Skip reward transaction verification
                JsonNode rewardNode = blockData.get("reward");
                if (rewardNode != null && rewardNode.isObject()) {
                    System.out.println("Skipping reward transaction: " + rewardNode.toPrettyString());
                } else if (rewardNode != null) {
                    System.out.println("Reward field present but not an object: " + rewardNode);
                } else {
                    System.out.println("No reward transaction in this block");
                }

                // Process user transaction in the 'data' field
                JsonNode userData = blockData.get("data");
                if (userData != null && userData.isTextual()) {
                    String userDataStr = userData.asText();
                    System.out.println("Found user data (JSON string): " + userDataStr);
                    JsonNode transaction;
                    try {
                        transaction = objectMapper.readTree(userDataStr);
                        System.out.println("Parsed user transaction: " + transaction.toPrettyString());
                        totalTransactions++;
                        boolean isValid = verifyTransactionSignature(transaction, totalTransactions, block.index);
                        if (isValid) {
                            validSignatures++;
                            System.out.println("User transaction #" + totalTransactions + " signature is VALID");
                        } else {
                            invalidSignatures++;
                            System.out.println("User transaction #" + totalTransactions + " signature is INVALID");
                        }
                    } catch (IOException e) {
                        System.err.println("Error parsing user data JSON string in block #" + block.index + ": " + e.getMessage());
                        e.printStackTrace();
                        totalTransactions++;
                        invalidSignatures++;
                        System.out.println("User transaction #" + totalTransactions + " signature is INVALID due to JSON parsing error");
                    }
                } else if (userData != null) {
                    System.out.println("User data present but not a JSON string: " + userData);
                } else {
                    System.out.println("No user transaction in this block");
                }
            }

            // Print summary
            System.out.println("\nVerification Summary:");
            System.out.println("Total blocks processed: " + blockchain.size());
            System.out.println("Total user transactions: " + totalTransactions);
            System.out.println("Valid signatures: " + validSignatures);
            System.out.println("Invalid signatures: " + invalidSignatures);
            System.out.println("Verification " + (invalidSignatures == 0 ? "SUCCESSFUL" : "FAILED"));

        } catch (Exception e) {
            System.err.println("Fatal error during verification: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Loads the blockchain from a compressed .gz file.
     */
    private static List<Node.Block> loadBlockchain() throws IOException {
        File file = new File(CHAIN_FILE);
        System.out.println("Checking for blockchain file at: " + file.getAbsolutePath());
        if (!file.exists()) {
            throw new IOException("Blockchain file not found: " + CHAIN_FILE);
        }
        System.out.println("Blockchain file found, size: " + file.length() + " bytes");

        try (GZIPInputStream gis = new GZIPInputStream(new FileInputStream(file));
             Reader isr = new InputStreamReader(gis, StandardCharsets.UTF_8);
             BufferedReader br = new BufferedReader(isr)) {
            System.out.println("Deserializing blockchain JSON...");
            List<Node.Block> blockchain = objectMapper.readValue(br, objectMapper.getTypeFactory()
                    .constructCollectionType(List.class, Node.Block.class));
            System.out.println("Deserialization complete, loaded " + blockchain.size() + " blocks");
            return blockchain;
        } catch (IOException e) {
            System.err.println("Error reading blockchain file: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Verifies the ECDSA signature of a user transaction with detailed logging.
     * Transaction JSON must contain: from, to, amount, signature, pubkey.
     * Signature is verified against the JSON-encoded string {"from":"...","to":"...","amount":...}.
     */
    private static boolean verifyTransactionSignature(JsonNode tx, int txNumber, int blockIndex) {
        System.out.println("\nVerifying signature for transaction #" + txNumber + " in block #" + blockIndex);
        try {
            // Log all fields in the transaction
            System.out.println("Transaction fields: ");
            tx.fieldNames().forEachRemaining(field -> 
                System.out.println("  - " + field + ": " + tx.get(field)));

            // Extract transaction fields
            String from = tx.has("from") ? tx.get("from").asText() : "";
            String to = tx.has("to") ? tx.get("to").asText() : "";
            int amount = tx.has("amount") ? tx.get("amount").asInt() : 0;
            String signatureB64 = tx.has("signature") ? tx.get("signature").asText() : "";
            String publicKeyB64 = tx.has("pubkey") ? tx.get("pubkey").asText() : "";

            // Check for missing fields
            if (from.isEmpty()) {
                System.out.println("Missing or empty 'from' field");
                return false;
            }
            if (to.isEmpty()) {
                System.out.println("Missing or empty 'to' field");
                return false;
            }
            if (signatureB64.isEmpty()) {
                System.out.println("Missing or empty 'signature' field");
                return false;
            }
            if (publicKeyB64.isEmpty()) {
                System.out.println("Missing or empty 'pubkey' field");
                return false;
            }
            System.out.println("All required fields present: from=" + from + ", to=" + to + ", amount=" + amount);

            // Reconstruct transaction message as JSON
            ObjectNode txCore = objectMapper.createObjectNode();
            txCore.put("from", from);
            txCore.put("to", to);
            txCore.put("amount", amount);
            String message = objectMapper.writeValueAsString(txCore);
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("Transaction message for signing (JSON): " + message);
            System.out.println("Message bytes (hex): " + bytesToHex(messageBytes));

            // Compute SHA-256 hash of the message for debugging
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = sha256.digest(messageBytes);
            System.out.println("SHA-256 hash of message (hex): " + bytesToHex(messageHash));

            // Decode public key (DER format)
            System.out.println("Decoding public key (Base64): " + publicKeyB64);
            byte[] pubKeyBytes;
            try {
                pubKeyBytes = Base64.getDecoder().decode(publicKeyB64);
                System.out.println("Public key bytes (hex): " + bytesToHex(pubKeyBytes));
            } catch (IllegalArgumentException e) {
                System.err.println("Invalid Base64 for public key: " + e.getMessage());
                e.printStackTrace();
                return false;
            }

            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PublicKey publicKey;
            try {
                publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
                System.out.println("Public key successfully decoded");
            } catch (Exception e) {
                System.err.println("Error decoding public key: " + e.getMessage());
                e.printStackTrace();
                return false;
            }

            // Decode signature
            System.out.println("Decoding signature (Base64): " + signatureB64);
            byte[] signatureBytes;
            try {
                signatureBytes = Base64.getDecoder().decode(signatureB64);
                System.out.println("Signature bytes (hex): " + bytesToHex(signatureBytes));
            } catch (IllegalArgumentException e) {
                System.err.println("Invalid Base64 for signature: " + e.getMessage());
                e.printStackTrace();
                return false;
            }

            // Verify signature
            System.out.println("Initializing ECDSA signature verification...");
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(messageBytes);
            boolean isValid = ecdsaVerify.verify(signatureBytes);
            System.out.println("Signature verification result: " + (isValid ? "VALID" : "INVALID"));
            return isValid;

        } catch (Exception e) {
            System.err.println("Unexpected error verifying transaction #" + txNumber + " in block #" + blockIndex + ": " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Converts a byte array to a hexadecimal string for logging.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        verifyBlockchainSignatures();
    }
}