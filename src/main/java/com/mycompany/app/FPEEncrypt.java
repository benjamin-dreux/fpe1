package com.mycompany.app;

import java.util.Map;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fpe.FPEEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.params.KeyParameter;

public class FPEEncrypt {
    
    private static final String FRENCH_ALPHABET =
            "abcdefghijklmnopqrstuvwxyz" +
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
            "àâäçéèêëîïôöùûüÿ" +
            "ÀÂÄÇÉÈÊËÎÏÔÖÙÛÜŸ" +
            "œŒæÆ" +
            " -'";
    private static final char[] ALPHABET = FRENCH_ALPHABET.toCharArray();
    private static final int RADIX = ALPHABET.length;

    private static final Map<Character, Byte> charToIndex = new HashMap<>();
    private static final Map<Byte, Character> indexToChar = new HashMap<>();

    static {
        for (int i = 0; i < ALPHABET.length; i++) {
            byte idx = (byte) i;
            charToIndex.put(ALPHABET[i], idx);
            indexToChar.put(idx, ALPHABET[i]);
        }
    }
    public static void main(String[] args) throws Exception {

        

        String input = captureInput();
        // Conversion texte -> indices (bytes)
        byte[] inSymbols = toSymbolBytes(input);

        // Clé AES 128 bits (exemple — à remplacer par une clé sécurisée)
        byte[] key = Hex.decode("00112233445566778899AABBCCDDEEFF");

        // Pas de tweak (peut être vide ou personnalisé)
        byte[] tweak = new byte[0];

        // Moteur FF1
        FPEEngine engine = new FPEFF1Engine();

        FPEParameters params = new FPEParameters(new KeyParameter(key), RADIX, tweak);

        engine.init(true, params); // true = chiffrement

        byte[] outSymbols = new byte[inSymbols.length];

        engine.processBlock(inSymbols, 0, inSymbols.length, outSymbols, 0);

        var outTxt = fromSymbolBytes(outSymbols);

        System.out.println("Texte chiffré : " + outTxt);
    }

     private static byte[] toSymbolBytes(String text) {
        byte[] res = new byte[text.length()];
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            Byte idx = charToIndex.get(c);
            if (idx == null) {
                throw new IllegalArgumentException("Caractère non supporté : " + c);
            }
            res[i] = idx;
        }
        return res;
    }

    private static String fromSymbolBytes(byte[] symbols) {
        StringBuilder sb = new StringBuilder();
        for (byte b : symbols) {
            Character c = indexToChar.get(b);
            if (c == null) {
                throw new IllegalStateException("Index inconnu : " + (b & 0xFF));
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static  String captureInput(){
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        try {
           return  reader.readLine();
        } catch (IOException e) {
            
            throw new RuntimeException(e);
        }
    }
}
