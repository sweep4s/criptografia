package com.criptografia;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * ============================================================================
 * CLASE: VigenereAnalyzer
 * ============================================================================
 * Sistema de criptoanálisis para cifrados polialfabéticos tipo Vigenère
 * sobre alfabetos dinámicos Zₙ de tamaño arbitrario.
 *
 * FUNDAMENTOS TEÓRICOS:
 *
 * 1. Índice de Coincidencia (IC) de Friedman (1922):
 *    Mide la probabilidad de que dos caracteres elegidos al azar sin reemplazo
 *    de un texto sean idénticos:
 *      IC = Σ fᵢ(fᵢ - 1) / [N(N - 1)]
 *    - Para texto español natural: IC ≈ 0.065 – 0.077
 *    - Para texto aleatorio equiprobable: IC ≈ 1/n
 *
 * 2. Principio de descomposición periódica (Kasiski/Friedman):
 *    Si la clave tiene longitud L, al extraer las posiciones c, c+L, c+2L, ...
 *    (columna c), todos esos caracteres fueron cifrados con el MISMO carácter
 *    de clave. Cada columna es un cifrado César monoalfabético cuyo IC
 *    debería alcanzar el nivel del lenguaje natural si L es correcto.
 *
 * 3. Resonancia armónica:
 *    Los múltiplos del período verdadero (2L, 3L, ...) también producen
 *    columnas monoalfabéticas, generando "armónicos" con IC elevado.
 *    El período fundamental es el menor L que explica estos armónicos.
 *
 * 4. Reconstrucción de clave (producto escalar / máxima verosimilitud):
 *    Para cada columna c y cada desplazamiento de prueba k en Zₙ:
 *      Score(k) = Σ q_obs(j) × P_español(j)
 *    donde q_obs se desplaza cíclicamente por k.
 *    El k que maximiza este score es el candidato para esa posición de clave.
 *
 * NOTA IMPORTANTE:
 *    La recuperación estadística de la clave es una ESTIMACIÓN. Puede fallar
 *    si el texto es corto, el alfabeto incluye símbolos inusuales, o el
 *    mensaje no sigue la distribución típica del español.
 * ============================================================================
 */
public class VigenereAnalyzer {

    /** Instancia del cifrador con el alfabeto dinámico configurado */
    private final VigenereCipher cipher;

    /** Vector de probabilidades teóricas del español normalizado a Zₙ */
    private final double[] spanishProbabilities;

    /** Candidatos top evaluados en la última deducción de clave */
    private List<List<CandidateShift>> lastTopCandidates = new ArrayList<>();

    // ========================================================================
    // CLASES AUXILIARES
    // ========================================================================

    /**
     * Resultado estructurado del análisis de picos y armónicos en la curva IC vs L.
     */
    public static class PeakDetectionResult {
        /** Período fundamental estimado */
        public final int bestL;
        /** Múltiplos de bestL que también mostraron IC elevado */
        public final List<Integer> harmonics;
        /** IC esperado para texto aleatorio equiprobable: 1/n */
        public final double baselineRandomIC;
        /** IC del período seleccionado como fundamental */
        public final double peakIC;
        /** Justificación textual del resultado */
        public final String rationale;

        public PeakDetectionResult(int bestL, List<Integer> harmonics,
                                   double baselineRandomIC, double peakIC, String rationale) {
            this.bestL = bestL;
            this.harmonics = harmonics;
            this.baselineRandomIC = baselineRandomIC;
            this.peakIC = peakIC;
            this.rationale = rationale;
        }
    }

    /**
     * Candidato a desplazamiento para una columna del criptograma.
     */
    public static class CandidateShift {
        /** Desplazamiento k en Zₙ */
        public final int shift;
        /** Carácter del alfabeto correspondiente a este desplazamiento */
        public final char keyChar;
        /** Puntuación de correlación con la distribución del español */
        public final double score;

        public CandidateShift(int shift, char keyChar, double score) {
            this.shift = shift;
            this.keyChar = keyChar;
            this.score = score;
        }
    }

    // ========================================================================
    // CONSTRUCTOR
    // ========================================================================

    /**
     * Construye un analizador para el cifrador dado.
     *
     * @param cipher Instancia de VigenereCipher con el alfabeto dinámico.
     */
    public VigenereAnalyzer(VigenereCipher cipher) {
        if (cipher == null) {
            throw new IllegalArgumentException("La instancia de VigenereCipher no puede ser nula.");
        }
        this.cipher = cipher;
        this.spanishProbabilities = buildSpanishDistribution(cipher);
    }

    // ========================================================================
    // DISTRIBUCIÓN DE FRECUENCIAS DEL ESPAÑOL
    // ========================================================================

    /**
     * Construye el vector de probabilidades del español adaptado al alfabeto Zₙ.
     * Cada carácter del alfabeto recibe un peso estadístico empírico del español.
     * El vector se normaliza para que sume 1.0.
     *
     * Si el alfabeto incluye dígitos u otros símbolos, se les asigna un peso
     * residual pequeño, ya que su frecuencia en textos naturales es baja.
     * Esto puede reducir la precisión del criptoanálisis si el texto cifrado
     * contiene muchos caracteres no alfabéticos.
     *
     * @param cipher Cifrador del cual se obtiene el alfabeto.
     * @return Vector normalizado de probabilidades.
     */
    private static double[] buildSpanishDistribution(VigenereCipher cipher) {
        int n = cipher.getAlphabetSize();
        double[] probs = new double[n];
        double sum = 0.0;

        for (int i = 0; i < n; i++) {
            char c = cipher.posToChar(i);
            double p = getBaseSpanishWeight(c);
            probs[i] = p;
            sum += p;
        }

        // Normalización estricta: Σ P[i] = 1.0
        if (sum > 0.0) {
            for (int i = 0; i < n; i++) {
                probs[i] /= sum;
            }
        } else {
            // Si ningún carácter tiene peso, distribución uniforme
            Arrays.fill(probs, 1.0 / n);
        }
        return probs;
    }

    /**
     * Pesos estadísticos empíricos del español para letras, espacio y dígitos.
     * Fuente: estadísticas de frecuencias del corpus RAE y similares.
     *
     * Los dígitos reciben peso residual (0.003) y otros símbolos peso mínimo (0.001).
     * El espacio tiene peso alto (0.17) ya que es el carácter más frecuente
     * cuando se incluye en el alfabeto.
     *
     * @param c Carácter a consultar.
     * @return Peso relativo aproximado (sin normalizar).
     */
    private static double getBaseSpanishWeight(char c) {
        char upper = Character.toUpperCase(c);
        switch (upper) {
            case 'E': return 0.1368;
            case 'A': return 0.1253;
            case 'O': return 0.0868;
            case 'S': return 0.0798;
            case 'R': return 0.0687;
            case 'N': return 0.0671;
            case 'I': return 0.0625;
            case 'D': return 0.0586;
            case 'L': return 0.0497;
            case 'C': return 0.0468;
            case 'T': return 0.0463;
            case 'U': return 0.0393;
            case 'M': return 0.0315;
            case 'P': return 0.0251;
            case 'B': return 0.0142;
            case 'G': return 0.0101;
            case 'V': return 0.0090;
            case 'Y': return 0.0090;
            case 'Q': return 0.0088;
            case 'H': return 0.0070;
            case 'F': return 0.0069;
            case 'Z': return 0.0052;
            case 'J': return 0.0044;
            case 'Ñ': return 0.0031;
            case 'X': return 0.0022;
            case 'K': return 0.0002;
            case 'W': return 0.0001;
            case ' ': return 0.1700; // Espacio: símbolo de mayor frecuencia si está en el alfabeto
            default:
                if (Character.isDigit(c)) {
                    return 0.0030; // Peso residual para dígitos (frecuencia baja en textos naturales)
                }
                return 0.0010; // Peso base para otros símbolos
        }
    }

    // ========================================================================
    // ÍNDICE DE COINCIDENCIA (IC)
    // ========================================================================

    /**
     * Calcula el Índice de Coincidencia (IC) de Friedman para un texto.
     *
     * Fórmula:
     *   IC = Σ fᵢ(fᵢ - 1) / [N(N - 1)]
     *
     * donde fᵢ es la frecuencia absoluta del carácter i-ésimo del alfabeto
     * y N es el número total de caracteres válidos analizados.
     *
     * Si N ≤ 1, retorna 0.0 para evitar división por cero.
     *
     * @param texto Texto a analizar (se filtran caracteres ajenos al alfabeto).
     * @return Valor del IC en el rango [0.0, 1.0].
     */
    public double calcularIC(String texto) {
        String clean = cipher.sanitize(texto);
        int totalChars = clean.length();

        // Control de división por cero: necesitamos al menos 2 caracteres
        if (totalChars <= 1) {
            return 0.0;
        }

        int n = cipher.getAlphabetSize();
        int[] freqs = new int[n];

        // Conteo de frecuencias absolutas
        for (int i = 0; i < totalChars; i++) {
            int pos = cipher.charToPos(clean.charAt(i));
            if (pos >= 0) {
                freqs[pos]++;
            }
        }

        // Cálculo del numerador: Σ fᵢ(fᵢ - 1)
        long sumNumerator = 0L;
        for (int f : freqs) {
            sumNumerator += (long) f * (f - 1);
        }

        // Denominador: N(N - 1)
        long denominator = (long) totalChars * (totalChars - 1);
        return (double) sumNumerator / (double) denominator;
    }

    // ========================================================================
    // TABLA IC vs L (con agregación ponderada)
    // ========================================================================

    /**
     * Calcula el IC agregado para cada longitud de clave L entre 1 y Lmax.
     *
     * Para cada L:
     * 1. Se divide el criptograma en L columnas (posiciones i mod L).
     * 2. Se calcula el IC de cada columna que tenga al menos 2 caracteres.
     * 3. Se obtiene un IC agregado PONDERADO por el número de pares de cada columna.
     *
     * JUSTIFICACIÓN DE LA PONDERACIÓN:
     *   El promedio simple trata igual a columnas con 100 caracteres que a
     *   columnas con 3. La ponderación por nᵢ(nᵢ-1) (número de pares) da
     *   más peso a columnas con más datos y produce estimaciones más estables.
     *   El IC ponderado equivale a:
     *     IC_pond = Σ ICᵢ × wᵢ / Σ wᵢ,  donde wᵢ = nᵢ(nᵢ - 1)
     *
     * @param criptograma Texto cifrado (se sanitiza internamente).
     * @param Lmax        Longitud máxima de clave a evaluar.
     * @return Arreglo de tamaño Lmax con los IC ponderados para L = 1, 2, ..., Lmax.
     */
    public double[] tablaICvsL(String criptograma, int Lmax) {
        String cleanCipher = cipher.sanitize(criptograma);
        if (Lmax < 1) Lmax = 1;
        double[] weightedICs = new double[Lmax];

        for (int L = 1; L <= Lmax; L++) {
            // Construir las L columnas
            StringBuilder[] columns = new StringBuilder[L];
            for (int c = 0; c < L; c++) {
                columns[c] = new StringBuilder();
            }
            for (int i = 0; i < cleanCipher.length(); i++) {
                columns[i % L].append(cleanCipher.charAt(i));
            }

            // Calcular IC ponderado: Σ ICᵢ × wᵢ / Σ wᵢ
            double sumWeightedIC = 0.0;
            long sumWeights = 0;

            for (int c = 0; c < L; c++) {
                int ni = columns[c].length();
                if (ni > 1) {
                    double ic = calcularIC(columns[c].toString());
                    // Peso = nᵢ(nᵢ - 1): número de pares posibles en esta columna
                    long weight = (long) ni * (ni - 1);
                    sumWeightedIC += ic * weight;
                    sumWeights += weight;
                }
                // Columnas con < 2 caracteres se ignoran (evitar división por cero)
            }

            weightedICs[L - 1] = (sumWeights > 0) ? (sumWeightedIC / sumWeights) : 0.0;
        }

        return weightedICs;
    }

    /**
     * Sobrecarga de conveniencia con Lmax = 15 por defecto.
     */
    public double[] tablaICvsL(String criptograma) {
        return tablaICvsL(criptograma, 15);
    }

    // ========================================================================
    // DETECCIÓN DE PERÍODO Y ARMÓNICOS
    // ========================================================================

    /**
     * Identifica el período fundamental L y sus armónicos a partir de la curva IC vs L.
     *
     * Criterio:
     * - Se calcula un umbral adaptativo al 55% del rango entre el IC aleatorio (1/n)
     *   y el IC máximo observado.
     * - Para cada L candidato, se evalúa una puntuación armónica que incluye el IC
     *   de L y los de sus múltiplos 2L y 3L (si están disponibles).
     * - El L con mayor puntuación armónica se selecciona como período fundamental.
     *
     * LIMITACIÓN: Un IC elevado no prueba definitivamente que L sea la longitud
     * correcta. En textos cortos o con distribución atípica, el resultado puede
     * ser incorrecto. Siempre se debe verificar el descifrado resultante.
     *
     * @param ics Arreglo con IC agregado para L = 1 .. Lmax.
     * @return Resultado con período fundamental, armónicos y justificación.
     */
    public PeakDetectionResult detectarPico(double[] ics) {
        int n = cipher.getAlphabetSize();
        double baselineRandom = 1.0 / n;
        int Lmax = ics.length;

        // Encontrar el IC máximo observado
        double maxIC = 0.0;
        for (double ic : ics) {
            if (ic > maxIC) maxIC = ic;
        }

        // Umbral adaptativo: 55% del camino entre baseline y el máximo
        double threshold = baselineRandom + 0.55 * (maxIC - baselineRandom);

        int bestL = 1;
        double bestHarmonicScore = -1.0;

        for (int L = 1; L <= Lmax; L++) {
            double currentIC = ics[L - 1];
            // Saltar valores por debajo del umbral (excepto L=1 que siempre se evalúa)
            if (currentIC < threshold && L > 1) {
                continue;
            }

            // Puntuación armónica: promedio de IC en L, 2L, 3L
            double harmonicScore = currentIC;
            int countHarmonics = 1;

            if (2 * L <= Lmax) {
                harmonicScore += ics[2 * L - 1];
                countHarmonics++;
            }
            if (3 * L <= Lmax) {
                harmonicScore += ics[3 * L - 1];
                countHarmonics++;
            }

            double avgHarmonic = harmonicScore / countHarmonics;
            if (avgHarmonic > bestHarmonicScore) {
                bestHarmonicScore = avgHarmonic;
                bestL = L;
            }
        }

        // Identificar armónicos explícitos del período fundamental
        List<Integer> detectedHarmonics = new ArrayList<>();
        for (int mult = 2; mult * bestL <= Lmax; mult++) {
            if (ics[mult * bestL - 1] >= threshold) {
                detectedHarmonics.add(mult * bestL);
            }
        }

        String rationale = String.format(Locale.US,
            "L=%d seleccionado como periodo fundamental: IC(L)=%.5f supera la linea base " +
            "aleatoria (1/n = %.5f). Armonicos corroborados en multiplos: %s. " +
            "NOTA: Este resultado es una estimacion estadistica, no una garantia.",
            bestL, ics[bestL - 1], baselineRandom, detectedHarmonics.toString());

        return new PeakDetectionResult(bestL, detectedHarmonics, baselineRandom, ics[bestL - 1], rationale);
    }

    // ========================================================================
    // VISUALIZACIÓN EN CONSOLA
    // ========================================================================

    /**
     * Imprime la tabla y gráfica de barras ASCII del IC vs L en la consola.
     * Detecta automáticamente el pico principal y marca los armónicos.
     *
     * Columnas mostradas:
     * - L: longitud de clave evaluada
     * - IC Pond: IC agregado ponderado por pares
     * - Gráfica de barras ASCII (# = pico, = = armónico, - = normal)
     * - Diagnóstico: clasificación del valor
     *
     * @param ics Arreglo con IC para L = 1 .. Lmax.
     */
    public void graficarICvsL(double[] ics) {
        PeakDetectionResult result = detectarPico(ics);
        graficarICvsL(ics, result);
    }

    /**
     * Sobrecarga que recibe el resultado de detección explícitamente.
     */
    public void graficarICvsL(double[] ics, PeakDetectionResult result) {
        int Lmax = ics.length;
        String sep = "+-----+----------+--------------------------------------------------+----------------------------+";
        System.out.println(sep);
        System.out.println("|  L  | IC Pond  | Grafica                                          | Diagnostico                |");
        System.out.println(sep);

        // Escala de la gráfica
        double maxVal = 0.09;
        for (double v : ics) {
            if (v > maxVal) maxVal = v * 1.05;
        }
        int maxBarLength = 48;

        for (int L = 1; L <= Lmax; L++) {
            double ic = ics[L - 1];
            int barWidth = (int) Math.round((ic / maxVal) * maxBarLength);
            barWidth = Math.max(0, Math.min(maxBarLength, barWidth));

            boolean isPeak = (L == result.bestL);
            boolean isHarmonic = result.harmonics.contains(L);

            // Caracteres ASCII compatibles con cualquier terminal
            char barChar = isPeak ? '#' : (isHarmonic ? '=' : '-');
            StringBuilder bar = new StringBuilder();
            for (int b = 0; b < barWidth; b++) {
                bar.append(barChar);
            }
            while (bar.length() < maxBarLength) {
                bar.append(' ');
            }

            String tag;
            if (isPeak) {
                tag = "[*] PICO PRINCIPAL (L=" + L + ")";
            } else if (isHarmonic) {
                int mult = L / result.bestL;
                tag = "[^] ARMONICO (" + mult + "x de L=" + result.bestL + ")";
            } else if (ic <= result.baselineRandomIC * 1.25) {
                tag = "[.] Nivel aleatorio";
            } else {
                tag = "[~] Mezcla parcial";
            }

            System.out.printf(Locale.US, "| %3d | %.5f  | %s | %-26s |%n",
                              L, ic, bar.toString(), tag);
        }
        System.out.println(sep);
        System.out.printf(Locale.US,
            " Referencia: IC Aleatorio (1/n) = %.5f | IC Espanol esperado ~ 0.065 - 0.077%n",
            result.baselineRandomIC);
    }

    // ========================================================================
    // ANÁLISIS DE FRECUENCIAS POR COLUMNAS Y RECUPERACIÓN DE CLAVE
    // ========================================================================

    /**
     * Muestra el conteo de frecuencias de cada columna del criptograma
     * para la longitud de clave dada.
     *
     * @param criptograma Texto cifrado.
     * @param L           Longitud de clave estimada.
     */
    public void mostrarFrecuenciasPorColumna(String criptograma, int L) {
        String cleanCipher = cipher.sanitize(criptograma);
        int n = cipher.getAlphabetSize();

        System.out.printf("%n--- Frecuencias por columna (L=%d) ---%n", L);

        for (int c = 0; c < L; c++) {
            // Extraer columna c
            StringBuilder colText = new StringBuilder();
            for (int i = c; i < cleanCipher.length(); i += L) {
                colText.append(cleanCipher.charAt(i));
            }

            int colLen = colText.length();
            int[] freqs = new int[n];
            for (int i = 0; i < colLen; i++) {
                int pos = cipher.charToPos(colText.charAt(i));
                if (pos >= 0) freqs[pos]++;
            }

            System.out.printf(Locale.US, "  Columna %2d (%d chars): ", c + 1, colLen);
            boolean first = true;
            for (int i = 0; i < n; i++) {
                if (freqs[i] > 0) {
                    if (!first) System.out.print(", ");
                    System.out.printf("'%c'=%d(%.1f%%)", cipher.posToChar(i), freqs[i],
                                      100.0 * freqs[i] / colLen);
                    first = false;
                }
            }
            System.out.println();
        }
    }

    /**
     * Reconstruye la palabra clave mediante análisis de frecuencias columna por columna.
     *
     * Para cada columna c del criptograma (con período L):
     * 1. Se cuentan las frecuencias de cada símbolo.
     * 2. Para cada desplazamiento candidato k en Zₙ, se calcula el producto escalar
     *    entre las frecuencias observadas desplazadas y la distribución teórica del español.
     * 3. El k con mayor score se selecciona como carácter de clave para esa posición.
     *
     * Se almacenan los top-3 candidatos para revisión del usuario.
     *
     * @param criptograma Texto cifrado.
     * @param L           Longitud de clave.
     * @return Clave deducida como cadena.
     */
    public String deducirClave(String criptograma, int L) {
        this.lastTopCandidates = new ArrayList<>();
        return deducirClave(criptograma, L, this.lastTopCandidates);
    }

    /**
     * Sobrecarga que permite recibir una lista externa para los candidatos.
     */
    public String deducirClave(String criptograma, int L, List<List<CandidateShift>> topCandidatesOutput) {
        String cleanCipher = cipher.sanitize(criptograma);
        int n = cipher.getAlphabetSize();
        StringBuilder deducedKey = new StringBuilder();

        if (topCandidatesOutput != null) {
            topCandidatesOutput.clear();
        }

        for (int c = 0; c < L; c++) {
            // Extraer subcriptograma de la columna c
            StringBuilder colText = new StringBuilder();
            for (int i = c; i < cleanCipher.length(); i += L) {
                colText.append(cleanCipher.charAt(i));
            }

            int colLen = colText.length();
            if (colLen == 0) {
                // Columna vacía: asignar primer carácter del alfabeto por defecto
                deducedKey.append(cipher.posToChar(0));
                continue;
            }

            // Contar frecuencias absolutas de la columna
            int[] colFreqs = new int[n];
            for (int i = 0; i < colLen; i++) {
                int pos = cipher.charToPos(colText.charAt(i));
                if (pos >= 0) {
                    colFreqs[pos]++;
                }
            }

            // Evaluar cada desplazamiento candidato k ∈ Zₙ
            List<CandidateShift> candidates = new ArrayList<>(n);
            for (int k = 0; k < n; k++) {
                double score = 0.0;
                for (int j = 0; j < n; j++) {
                    // Desplazar la posición del criptograma por k (usando Math.floorMod)
                    int cipherPos = Math.floorMod(j + k, n);
                    // Frecuencia relativa observada en la posición desplazada
                    double obsRelFreq = (double) colFreqs[cipherPos] / colLen;
                    // Producto escalar: correlación con la distribución esperada del español
                    score += obsRelFreq * spanishProbabilities[j];
                }
                candidates.add(new CandidateShift(k, cipher.posToChar(k), score));
            }

            // Ordenar por score descendente (máxima verosimilitud primero)
            candidates.sort(Comparator.comparingDouble((CandidateShift cs) -> cs.score).reversed());

            // Guardar top-3 candidatos para revisión
            if (topCandidatesOutput != null) {
                topCandidatesOutput.add(candidates.subList(0, Math.min(3, candidates.size())));
            }

            // El mejor candidato define el carácter de clave para esta posición
            deducedKey.append(candidates.get(0).keyChar);
        }

        return deducedKey.toString();
    }

    /**
     * Devuelve los candidatos top evaluados en la última llamada a deducirClave.
     */
    public List<List<CandidateShift>> getLastTopCandidates() {
        return lastTopCandidates;
    }

    /**
     * Descifra delegando en VigenereCipher.decrypt().
     */
    public String descifrar(String criptograma, String clave) {
        return cipher.decrypt(criptograma, clave);
    }

    // ========================================================================
    // UTILIDADES DE LECTURA DE ARCHIVOS
    // ========================================================================

    /**
     * Elimina saltos de línea finales (\r, \n) de una cadena.
     * Preserva espacios y otros caracteres válidos del alfabeto.
     */
    public static String stripLineEndings(String text) {
        if (text == null) return "";
        int end = text.length();
        while (end > 0 && (text.charAt(end - 1) == '\r' || text.charAt(end - 1) == '\n')) {
            end--;
        }
        return text.substring(0, end);
    }

    /**
     * Lee un archivo de texto completo en UTF-8, eliminando saltos de línea finales.
     *
     * @param filepath Ruta al archivo.
     * @return Contenido del archivo como cadena.
     * @throws IOException Si el archivo no existe o no se puede leer.
     */
    public static String readFileUtf8(String filepath) throws IOException {
        Path p = Paths.get(filepath);
        if (!Files.exists(p)) {
            throw new IOException("Archivo no encontrado: " + filepath);
        }
        if (Files.size(p) == 0) {
            throw new IOException("El archivo esta vacio: " + filepath);
        }
        byte[] bytes = Files.readAllBytes(p);
        String content = new String(bytes, StandardCharsets.UTF_8);
        return stripLineEndings(content);
    }

    /**
     * Exporta los datos de IC vs L a un archivo CSV para graficación externa.
     *
     * @param ics      Arreglo de IC por longitud de clave.
     * @param filepath Ruta del archivo CSV a generar.
     * @throws IOException Si no se puede escribir el archivo.
     */
    public void exportarCSV(double[] ics, String filepath) throws IOException {
        StringBuilder csv = new StringBuilder();
        csv.append("L,IC_Ponderado\n");
        for (int i = 0; i < ics.length; i++) {
            csv.append(String.format(Locale.US, "%d,%.6f%n", i + 1, ics[i]));
        }
        Files.write(Paths.get(filepath), csv.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("[+] Datos exportados a: " + filepath);
    }
}
