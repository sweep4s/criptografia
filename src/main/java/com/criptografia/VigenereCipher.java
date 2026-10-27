package com.criptografia;

import java.util.HashMap;
import java.util.Map;

/**
 * ============================================================================
 * CLASE: VigenereCipher
 * ============================================================================
 * Implementación manual del Cifrado de Vigenère generalizado sobre un
 * alfabeto dinámico de tamaño N, trabajando en el anillo Zₙ = Z / nZ.
 *
 * OPERACIONES CRIPTOGRÁFICAS:
 *   Cifrado:    cᵢ = (mᵢ + k_{i mod L}) mod n
 *   Descifrado: mᵢ = (cᵢ - k_{i mod L}) mod n
 *
 * Se utiliza Math.floorMod() en lugar del operador '%' de Java, ya que
 * este último devuelve valores negativos cuando el dividendo es negativo
 * (caso frecuente en el descifrado), lo que causaría errores de índice.
 *
 * POLÍTICA PARA CARACTERES AJENOS AL ALFABETO:
 *   Los caracteres que no pertenecen al alfabeto configurado se CONSERVAN
 *   en su posición original sin cifrar/descifrar, y NO avanzan el índice
 *   de la clave. Esto garantiza que cifrar y luego descifrar recupere
 *   exactamente el texto original, incluyendo espacios, signos de
 *   puntuación, saltos de línea, etc., cuando no forman parte del alfabeto.
 *
 * VALIDACIONES:
 *   - El alfabeto debe tener al menos 2 caracteres sin duplicados.
 *   - La clave debe contener al menos un carácter válido del alfabeto.
 *   - Si el alfabeto contiene solo mayúsculas (sin minúsculas), el texto
 *     de entrada se normaliza a mayúsculas automáticamente.
 * ============================================================================
 */
public class VigenereCipher {

    /** Alfabeto canónico ordenado como cadena */
    private final String alphabet;

    /** Cardinalidad del alfabeto n = |Zₙ| */
    private final int alphabetSize;

    /** Mapeo O(1): Carácter → Índice en Zₙ */
    private final Map<Character, Integer> charToIndex;

    /** Mapeo inverso O(1): Índice en Zₙ → Carácter */
    private final char[] indexToChar;

    /** Indica si el alfabeto contiene solo mayúsculas (para normalización automática) */
    private final boolean isOnlyUppercase;

    /**
     * Construye un cifrador Vigenère con un alfabeto dinámico personalizado.
     *
     * @param customAlphabet Cadena con los caracteres del alfabeto (sin duplicados, mínimo 2).
     * @throws IllegalArgumentException si el alfabeto es inválido.
     */
    public VigenereCipher(String customAlphabet) {
        // Validación: no nulo y longitud mínima
        if (customAlphabet == null || customAlphabet.length() < 2) {
            throw new IllegalArgumentException(
                "El alfabeto debe contener al menos 2 caracteres. Recibido: " +
                (customAlphabet == null ? "null" : "\"" + customAlphabet + "\" (longitud " + customAlphabet.length() + ")"));
        }

        this.alphabet = customAlphabet;
        this.alphabetSize = customAlphabet.length();
        this.charToIndex = new HashMap<>(alphabetSize * 2);
        this.indexToChar = new char[alphabetSize];

        boolean hasUpper = false;
        boolean hasLower = false;

        // Construir los mapeos bidireccionales y validar duplicados
        for (int i = 0; i < alphabetSize; i++) {
            char c = customAlphabet.charAt(i);
            if (charToIndex.containsKey(c)) {
                throw new IllegalArgumentException(
                    "Carácter duplicado en el alfabeto: '" + c + "' (posición " + i + ")");
            }
            charToIndex.put(c, i);
            indexToChar[i] = c;

            if (Character.isUpperCase(c)) hasUpper = true;
            if (Character.isLowerCase(c)) hasLower = true;
        }

        // Si el alfabeto tiene mayúsculas pero no minúsculas, se normalizará a mayúsculas
        this.isOnlyUppercase = hasUpper && !hasLower;
    }

    /** @return Tamaño del alfabeto (n). */
    public int getAlphabetSize() {
        return alphabetSize;
    }

    /** @return Cadena del alfabeto configurado. */
    public String getAlphabet() {
        return alphabet;
    }

    /** @return true si el alfabeto es solo mayúsculas y se normalizarán las minúsculas. */
    public boolean isOnlyUppercase() {
        return isOnlyUppercase;
    }

    /**
     * Convierte un carácter a su índice en Zₙ.
     * Si el alfabeto es solo mayúsculas y se recibe una minúscula,
     * se intenta buscar su equivalente en mayúsculas.
     *
     * @param c Carácter a buscar.
     * @return Índice en [0, n-1], o -1 si el carácter no pertenece al alfabeto.
     */
    public int charToPos(char c) {
        Integer idx = charToIndex.get(c);
        if (idx != null) {
            return idx;
        }
        // Normalización automática: minúscula → mayúscula si aplica
        if (isOnlyUppercase && Character.isLowerCase(c)) {
            Integer upperIdx = charToIndex.get(Character.toUpperCase(c));
            if (upperIdx != null) {
                return upperIdx;
            }
        }
        return -1;
    }

    /**
     * Convierte un índice en Zₙ al carácter correspondiente del alfabeto.
     * Usa Math.floorMod para blindar contra índices negativos o fuera de rango.
     *
     * @param pos Índice (puede ser negativo, se normaliza con módulo).
     * @return Carácter en la posición normalizada.
     */
    public char posToChar(int pos) {
        int safeIndex = Math.floorMod(pos, alphabetSize);
        return indexToChar[safeIndex];
    }

    /**
     * Valida que una clave contenga al menos un carácter válido del alfabeto.
     *
     * @param key Clave a validar.
     * @throws IllegalArgumentException si la clave es nula, vacía o sin caracteres válidos.
     */
    public void validateKey(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("La clave no puede ser nula ni vacía.");
        }
        boolean hasValid = false;
        for (int i = 0; i < key.length(); i++) {
            if (charToPos(key.charAt(i)) >= 0) {
                hasValid = true;
                break;
            }
        }
        if (!hasValid) {
            throw new IllegalArgumentException(
                "La clave no contiene ningún carácter válido del alfabeto: \"" + key + "\"");
        }
    }

    /**
     * Filtra y normaliza una cadena eliminando caracteres ajenos al alfabeto.
     * Útil para preparar el criptograma antes del análisis estadístico.
     *
     * @param input Texto de entrada.
     * @return Cadena con solo caracteres del alfabeto (normalizados si aplica).
     */
    public String sanitize(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int pos = charToPos(c);
            if (pos >= 0) {
                // Usar posToChar para obtener la forma canónica (normalizada)
                sb.append(posToChar(pos));
            }
        }
        return sb.toString();
    }

    /**
     * Cifra un mensaje usando el algoritmo de Vigenère generalizado.
     *
     * Fórmula: cᵢ = (mᵢ + k_{j mod L}) mod n
     *
     * Los caracteres ajenos al alfabeto se conservan sin cifrar y NO avanzan
     * el índice j de la clave.
     *
     * @param plaintext Texto en claro.
     * @param key       Clave de cifrado (debe contener caracteres del alfabeto).
     * @return Texto cifrado.
     */
    public String encrypt(String plaintext, String key) {
        validateKey(key);
        // Extraer solo los desplazamientos válidos de la clave
        int[] keyShifts = extractKeyShifts(key);
        int keyLen = keyShifts.length;

        StringBuilder ciphertext = new StringBuilder(plaintext.length());
        int keyIndex = 0; // Índice en la clave (solo avanza con caracteres del alfabeto)

        for (int i = 0; i < plaintext.length(); i++) {
            char c = plaintext.charAt(i);
            int pIdx = charToPos(c);

            if (pIdx >= 0) {
                // Carácter del alfabeto: cifrar con suma modular en Zₙ
                int kIdx = keyShifts[keyIndex % keyLen];
                int cIdx = Math.floorMod(pIdx + kIdx, alphabetSize);
                ciphertext.append(posToChar(cIdx));
                keyIndex++; // Solo avanza la clave para caracteres del alfabeto
            } else {
                // Carácter ajeno al alfabeto: se conserva sin cifrar, no avanza la clave
                ciphertext.append(c);
            }
        }

        return ciphertext.toString();
    }

    /**
     * Descifra un criptograma usando el inverso aditivo modular en Zₙ.
     *
     * Fórmula: mᵢ = (cᵢ - k_{j mod L}) mod n
     *
     * Se usa Math.floorMod para garantizar un resultado no negativo.
     * Los caracteres ajenos al alfabeto se conservan sin descifrar.
     *
     * @param ciphertext Texto cifrado.
     * @param key        Clave de descifrado.
     * @return Texto en claro recuperado.
     */
    public String decrypt(String ciphertext, String key) {
        validateKey(key);
        int[] keyShifts = extractKeyShifts(key);
        int keyLen = keyShifts.length;

        StringBuilder plaintext = new StringBuilder(ciphertext.length());
        int keyIndex = 0;

        for (int i = 0; i < ciphertext.length(); i++) {
            char c = ciphertext.charAt(i);
            int cIdx = charToPos(c);

            if (cIdx >= 0) {
                // Descifrar con resta modular en Zₙ usando Math.floorMod
                int kIdx = keyShifts[keyIndex % keyLen];
                int pIdx = Math.floorMod(cIdx - kIdx, alphabetSize);
                plaintext.append(posToChar(pIdx));
                keyIndex++;
            } else {
                // Carácter ajeno: conservar tal cual
                plaintext.append(c);
            }
        }

        return plaintext.toString();
    }

    /**
     * Extrae los desplazamientos (índices en Zₙ) de los caracteres válidos de la clave.
     * Los caracteres de la clave ajenos al alfabeto se ignoran.
     *
     * @param key Clave de texto.
     * @return Arreglo de enteros con los desplazamientos.
     * @throws IllegalArgumentException si no hay caracteres válidos.
     */
    private int[] extractKeyShifts(String key) {
        // Contar caracteres válidos
        int count = 0;
        for (int i = 0; i < key.length(); i++) {
            if (charToPos(key.charAt(i)) >= 0) count++;
        }
        if (count == 0) {
            throw new IllegalArgumentException(
                "La clave no contiene ningún carácter válido del alfabeto.");
        }

        int[] shifts = new int[count];
        int j = 0;
        for (int i = 0; i < key.length(); i++) {
            int pos = charToPos(key.charAt(i));
            if (pos >= 0) {
                shifts[j++] = pos;
            }
        }
        return shifts;
    }
}
