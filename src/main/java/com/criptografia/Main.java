package com.criptografia;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

/**
 * ============================================================================
 * CLASE: Main
 * ============================================================================
 * Programa principal de consola para el toolkit de criptoanálisis de Vigenère.
 *
 * Permite al usuario:
 * 1. Configurar un alfabeto personalizado (desde archivo, por consola o predefinido).
 * 2. Cargar un criptograma (desde archivo o por consola).
 * 3. Calcular y mostrar el Índice de Coincidencia para L = 1..15.
 * 4. Analizar picos y armónicos para estimar la longitud de clave.
 * 5. Ejecutar análisis de frecuencias por columnas.
 * 6. Deducir automáticamente la clave más probable.
 * 7. Descifrar el criptograma.
 * 8. Probar con una clave conocida.
 * 9. Cifrar un mensaje nuevo.
 *
 * Diseñado para ejecución rápida en laboratorio presencial.
 * ============================================================================
 */
public class Main {

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("==============================================================================");
        System.out.println("  TOOLKIT DE CRIPTOANALISIS DE VIGENERE GENERALIZADO");
        System.out.println("  Cifrado polialfabetico sobre anillos Zn de tamaño arbitrario");
        System.out.println("  Sin librerias externas - Implementacion manual completa");
        System.out.println("==============================================================================");

        // ------------------------------------------------------------------
        // PASO 1: Configurar el alfabeto
        // ------------------------------------------------------------------
        VigenereCipher cipher = null;
        while (cipher == null) {
            cipher = configurarAlfabeto();
        }

        int n = cipher.getAlphabetSize();
        System.out.printf("%n[OK] Alfabeto configurado: \"%s\"%n", cipher.getAlphabet());
        System.out.printf("[OK] Tamaño del alfabeto (n): %d caracteres%n", n);
        System.out.printf("[OK] IC aleatorio esperado (1/n): %.5f%n%n", 1.0 / n);

        // ------------------------------------------------------------------
        // PASO 2: Cargar el criptograma
        // ------------------------------------------------------------------
        String criptograma = null;
        while (criptograma == null || criptograma.isEmpty()) {
            criptograma = cargarCriptograma();
            if (criptograma == null || criptograma.isEmpty()) {
                System.out.println("[!] No se pudo cargar el criptograma. Intente de nuevo.");
            }
        }

        String cleanCipher = cipher.sanitize(criptograma);
        System.out.printf("[OK] Criptograma cargado: %d caracteres totales, %d caracteres del alfabeto.%n%n",
                          criptograma.length(), cleanCipher.length());

        if (cleanCipher.length() < 2) {
            System.out.println("[ERROR] El criptograma no contiene suficientes caracteres del alfabeto para analizar.");
            System.out.println("[INFO] Necesita al menos 2 caracteres del alfabeto.");
            return;
        }

        // ------------------------------------------------------------------
        // Bucle principal del menú
        // ------------------------------------------------------------------
        VigenereAnalyzer analyzer = new VigenereAnalyzer(cipher);
        String ultimaClave = null;

        boolean continuar = true;
        while (continuar) {
            System.out.println("\n==============================================================================");
            System.out.println("  MENU PRINCIPAL");
            System.out.println("==============================================================================");
            System.out.println("  1. Calcular IC para L = 1..15 (tabla y grafica)");
            System.out.println("  2. Analisis automatico completo (IC + clave + descifrado)");
            System.out.println("  3. Descifrar con clave conocida");
            System.out.println("  4. Cifrar un mensaje");
            System.out.println("  5. Ver frecuencias por columna (requiere longitud L)");
            System.out.println("  6. Exportar IC a CSV");
            System.out.println("  7. Cargar otro criptograma");
            System.out.println("  8. Cambiar alfabeto");
            System.out.println("  0. Salir");
            System.out.println("==============================================================================");
            System.out.print("  Seleccione una opcion: ");

            String opcion = scanner.nextLine().trim();

            switch (opcion) {
                case "1":
                    ejecutarAnalisisIC(analyzer, cleanCipher);
                    break;

                case "2":
                    ultimaClave = ejecutarAnalisisCompleto(analyzer, cleanCipher, criptograma);
                    break;

                case "3":
                    descifrarConClave(cipher, criptograma);
                    break;

                case "4":
                    cifrarMensaje(cipher);
                    break;

                case "5":
                    analizarFrecuencias(analyzer, cleanCipher);
                    break;

                case "6":
                    exportarCSV(analyzer, cleanCipher);
                    break;

                case "7":
                    criptograma = null;
                    while (criptograma == null || criptograma.isEmpty()) {
                        criptograma = cargarCriptograma();
                    }
                    cleanCipher = cipher.sanitize(criptograma);
                    System.out.printf("[OK] Nuevo criptograma: %d chars totales, %d del alfabeto.%n",
                                      criptograma.length(), cleanCipher.length());
                    break;

                case "8":
                    cipher = null;
                    while (cipher == null) {
                        cipher = configurarAlfabeto();
                    }
                    analyzer = new VigenereAnalyzer(cipher);
                    cleanCipher = cipher.sanitize(criptograma);
                    System.out.printf("[OK] Nuevo alfabeto: \"%s\" (n=%d)%n",
                                      cipher.getAlphabet(), cipher.getAlphabetSize());
                    break;

                case "0":
                    continuar = false;
                    System.out.println("\n[OK] Sesion finalizada. Hasta pronto.");
                    break;

                default:
                    System.out.println("[!] Opcion no reconocida.");
            }
        }
    }

    // ========================================================================
    // CONFIGURACIÓN DEL ALFABETO
    // ========================================================================

    /**
     * Permite al usuario configurar el alfabeto por diferentes vías.
     * @return VigenereCipher configurado, o null si hubo error.
     */
    private static VigenereCipher configurarAlfabeto() {
        System.out.println("\n--- CONFIGURACION DEL ALFABETO ---");
        System.out.println("  1. Alfabeto español extendido n=37 (A-Z + 0-9 + espacio)");
        System.out.println("  2. Alfabeto clasico n=26 (A-Z, sin Ñ ni espacio)");
        System.out.println("  3. Alfabeto español clasico n=27 (A-Z + Ñ)");
        System.out.println("  4. Cargar desde archivo .txt");
        System.out.println("  5. Escribir manualmente por consola");
        System.out.print("  Seleccione una opcion: ");

        String opcion = scanner.nextLine().trim();
        String alphabetStr;

        switch (opcion) {
            case "1":
                alphabetStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
                break;
            case "2":
                alphabetStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                break;
            case "3":
                alphabetStr = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";
                break;
            case "4":
                System.out.print("  Ruta del archivo de alfabeto: ");
                String path = scanner.nextLine().trim();
                try {
                    alphabetStr = VigenereAnalyzer.readFileUtf8(path);
                } catch (IOException e) {
                    System.out.println("[ERROR] " + e.getMessage());
                    return null;
                }
                break;
            case "5":
                System.out.print("  Escriba el alfabeto (todos los caracteres en una linea): ");
                alphabetStr = scanner.nextLine();
                break;
            default:
                System.out.println("[!] Opcion no valida. Usando alfabeto n=37 por defecto.");
                alphabetStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
        }

        try {
            VigenereCipher cipher = new VigenereCipher(alphabetStr);
            return cipher;
        } catch (IllegalArgumentException e) {
            System.out.println("[ERROR] Alfabeto invalido: " + e.getMessage());
            return null;
        }
    }

    // ========================================================================
    // CARGA DEL CRIPTOGRAMA
    // ========================================================================

    /**
     * Permite cargar el criptograma desde archivo o por consola.
     * @return Texto del criptograma, o null si hubo error.
     */
    private static String cargarCriptograma() {
        System.out.println("\n--- CARGA DEL CRIPTOGRAMA ---");
        System.out.println("  1. Cargar desde archivo .txt");
        System.out.println("  2. Pegar/escribir por consola");
        System.out.print("  Seleccione una opcion: ");

        String opcion = scanner.nextLine().trim();

        switch (opcion) {
            case "1":
                System.out.print("  Ruta del archivo del criptograma: ");
                String path = scanner.nextLine().trim();
                try {
                    String content = VigenereAnalyzer.readFileUtf8(path);
                    return content;
                } catch (IOException e) {
                    System.out.println("[ERROR] " + e.getMessage());
                    return null;
                }

            case "2":
                System.out.println("  Escriba o pegue el criptograma (presione Enter al terminar):");
                System.out.print("  > ");
                return scanner.nextLine();

            default:
                System.out.println("[!] Opcion no valida.");
                return null;
        }
    }

    // ========================================================================
    // OPCIÓN 1: Solo IC
    // ========================================================================

    /**
     * Calcula y muestra la tabla de IC para L = 1..15.
     */
    private static void ejecutarAnalisisIC(VigenereAnalyzer analyzer, String cleanCipher) {
        System.out.println("\n>>> CALCULO DEL INDICE DE COINCIDENCIA (L = 1..15)");
        System.out.println("------------------------------------------------------------------------------");

        double[] ics = analyzer.tablaICvsL(cleanCipher, 15);
        VigenereAnalyzer.PeakDetectionResult peak = analyzer.detectarPico(ics);
        analyzer.graficarICvsL(ics, peak);

        System.out.println("\n  RESULTADO:");
        System.out.printf("  -> Periodo fundamental estimado: L = %d%n", peak.bestL);
        System.out.printf(Locale.US, "  -> IC del pico: %.5f%n", peak.peakIC);
        if (!peak.harmonics.isEmpty()) {
            System.out.print("  -> Armonicos detectados: ");
            for (int h : peak.harmonics) {
                System.out.printf("L=%d (x%d)  ", h, h / peak.bestL);
            }
            System.out.println();
            System.out.println("  -> Los armonicos son multiplos del periodo fundamental.");
            System.out.println("     El periodo verdadero suele ser el menor L con IC elevado.");
        }
        System.out.println();
        System.out.println("  NOTA: Un IC elevado es una estimacion, no una garantia.");
        System.out.println("  Textos cortos o con distribucion atipica pueden producir falsos positivos.");
    }

    // ========================================================================
    // OPCIÓN 2: Análisis completo
    // ========================================================================

    /**
     * Ejecuta el análisis completo: IC → longitud → clave → descifrado.
     * @return La clave deducida o null.
     */
    private static String ejecutarAnalisisCompleto(VigenereAnalyzer analyzer,
                                                    String cleanCipher,
                                                    String criptogramaOriginal) {
        // Paso 2a: Tabla de IC
        System.out.println("\n==============================================================================");
        System.out.println("  ANALISIS AUTOMATICO COMPLETO");
        System.out.println("==============================================================================");

        double[] ics = analyzer.tablaICvsL(cleanCipher, 15);
        VigenereAnalyzer.PeakDetectionResult peak = analyzer.detectarPico(ics);

        System.out.println("\n>>> PASO 1/4: Tabla de Indice de Coincidencia");
        analyzer.graficarICvsL(ics, peak);

        System.out.printf(Locale.US, "%n  Periodo estimado: L = %d (IC = %.5f)%n", peak.bestL, peak.peakIC);
        if (!peak.harmonics.isEmpty()) {
            System.out.print("  Armonicos: ");
            for (int h : peak.harmonics) {
                System.out.printf("L=%d ", h);
            }
            System.out.println();
        }

        // Paso 2b: Permitir al usuario confirmar o cambiar L
        System.out.printf("%n  ¿Usar L=%d? (Enter para confirmar, o escriba otro valor): ", peak.bestL);
        String input = scanner.nextLine().trim();
        int selectedL = peak.bestL;
        if (!input.isEmpty()) {
            try {
                selectedL = Integer.parseInt(input);
                if (selectedL < 1 || selectedL > 50) {
                    System.out.println("[!] Valor fuera de rango. Usando L=" + peak.bestL);
                    selectedL = peak.bestL;
                }
            } catch (NumberFormatException e) {
                System.out.println("[!] Entrada invalida. Usando L=" + peak.bestL);
                selectedL = peak.bestL;
            }
        }

        // Paso 2c: Análisis de frecuencias por columnas
        System.out.printf("%n>>> PASO 2/4: Analisis de frecuencias por columnas (L=%d)%n", selectedL);
        analyzer.mostrarFrecuenciasPorColumna(cleanCipher, selectedL);

        // Paso 2d: Deducción de clave
        System.out.println("\n>>> PASO 3/4: Reconstruccion de la clave");
        System.out.println("------------------------------------------------------------------------------");
        List<List<VigenereAnalyzer.CandidateShift>> topPerColumn = new java.util.ArrayList<>();
        String recoveredKey = analyzer.deducirClave(cleanCipher, selectedL, topPerColumn);

        System.out.printf("  Evaluacion de desplazamientos (Top-3 por columna, L=%d):%n", selectedL);
        for (int col = 0; col < topPerColumn.size(); col++) {
            System.out.printf("    Columna %2d: ", col + 1);
            List<VigenereAnalyzer.CandidateShift> topList = topPerColumn.get(col);
            for (int r = 0; r < topList.size(); r++) {
                VigenereAnalyzer.CandidateShift cs = topList.get(r);
                System.out.printf(Locale.US, "#%d:'%c'(k=%d,s=%.4f) ",
                                  r + 1, cs.keyChar, cs.shift, cs.score);
            }
            System.out.println();
        }

        System.out.println("\n  ==================================================");
        System.out.println("  CLAVE ESTIMADA: \"" + recoveredKey + "\"");
        System.out.println("  ==================================================");
        System.out.println("  NOTA: Esta es una estimacion estadistica.");
        System.out.println("  Verifique que el texto descifrado tenga sentido.");

        // Paso 2e: Descifrado
        System.out.println("\n>>> PASO 4/4: Descifrado con la clave estimada");
        System.out.println("------------------------------------------------------------------------------");
        String decrypted = analyzer.descifrar(criptogramaOriginal, recoveredKey);

        mostrarTextoDescifrado(decrypted);

        double finalIC = analyzer.calcularIC(decrypted);
        System.out.printf(Locale.US, "%n  IC del texto descifrado: %.5f%n", finalIC);
        if (finalIC > 0.055) {
            System.out.println("  -> IC compatible con lenguaje natural (buen indicador).");
        } else {
            System.out.println("  -> IC bajo para lenguaje natural. La clave podria ser incorrecta.");
        }

        return recoveredKey;
    }

    // ========================================================================
    // OPCIÓN 3: Descifrar con clave conocida
    // ========================================================================

    /**
     * Descifra usando una clave proporcionada por el usuario.
     */
    private static void descifrarConClave(VigenereCipher cipher, String criptograma) {
        System.out.println("\n--- DESCIFRADO CON CLAVE CONOCIDA ---");
        System.out.print("  Introduzca la clave: ");
        String key = scanner.nextLine();

        try {
            cipher.validateKey(key);
            String decrypted = cipher.decrypt(criptograma, key);

            System.out.println("\n  TEXTO DESCIFRADO:");
            mostrarTextoDescifrado(decrypted);

            VigenereAnalyzer tempAnalyzer = new VigenereAnalyzer(cipher);
            double ic = tempAnalyzer.calcularIC(decrypted);
            System.out.printf(Locale.US, "%n  IC del texto descifrado: %.5f%n", ic);

        } catch (IllegalArgumentException e) {
            System.out.println("[ERROR] " + e.getMessage());
        }
    }

    // ========================================================================
    // OPCIÓN 4: Cifrar un mensaje
    // ========================================================================

    /**
     * Cifra un mensaje proporcionado por el usuario.
     */
    private static void cifrarMensaje(VigenereCipher cipher) {
        System.out.println("\n--- CIFRADO DE MENSAJE ---");
        System.out.print("  Escriba el mensaje a cifrar: ");
        String message = scanner.nextLine();
        System.out.print("  Escriba la clave: ");
        String key = scanner.nextLine();

        try {
            cipher.validateKey(key);
            String encrypted = cipher.encrypt(message, key);
            System.out.println("\n  TEXTO CIFRADO:");
            System.out.println("  " + encrypted);

            // Verificación: descifrar debe recuperar el original
            String verify = cipher.decrypt(encrypted, key);
            System.out.println("\n  VERIFICACION (descifrado del cifrado):");
            System.out.println("  " + verify);

            if (verify.equals(message) || verify.equals(cipher.isOnlyUppercase()
                    ? message.toUpperCase() : message)) {
                System.out.println("  [OK] Verificacion exitosa: cifrado y descifrado son consistentes.");
            } else {
                System.out.println("  [!] Nota: Puede haber diferencias en caracteres ajenos al alfabeto.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("[ERROR] " + e.getMessage());
        }
    }

    // ========================================================================
    // OPCIÓN 5: Frecuencias por columna
    // ========================================================================

    /**
     * Muestra el análisis de frecuencias para una longitud L indicada por el usuario.
     */
    private static void analizarFrecuencias(VigenereAnalyzer analyzer, String cleanCipher) {
        System.out.print("\n  Introduzca la longitud de clave L: ");
        String input = scanner.nextLine().trim();
        try {
            int L = Integer.parseInt(input);
            if (L < 1) {
                System.out.println("[ERROR] L debe ser al menos 1.");
                return;
            }
            analyzer.mostrarFrecuenciasPorColumna(cleanCipher, L);
        } catch (NumberFormatException e) {
            System.out.println("[ERROR] Valor numerico invalido.");
        }
    }

    // ========================================================================
    // OPCIÓN 6: Exportar CSV
    // ========================================================================

    /**
     * Exporta los datos IC vs L a un archivo CSV.
     */
    private static void exportarCSV(VigenereAnalyzer analyzer, String cleanCipher) {
        System.out.print("\n  Ruta del archivo CSV de salida (ej: ic_datos.csv): ");
        String path = scanner.nextLine().trim();
        if (path.isEmpty()) {
            path = "ic_datos.csv";
        }
        try {
            double[] ics = analyzer.tablaICvsL(cleanCipher, 15);
            analyzer.exportarCSV(ics, path);
        } catch (IOException e) {
            System.out.println("[ERROR] No se pudo escribir el archivo: " + e.getMessage());
        }
    }

    // ========================================================================
    // UTILIDADES
    // ========================================================================

    /**
     * Muestra un texto largo formateado en líneas de 80 caracteres.
     */
    private static void mostrarTextoDescifrado(String texto) {
        System.out.println("  --------------------------------------------------------------------------");
        int lineLength = 80;
        for (int i = 0; i < texto.length(); i += lineLength) {
            int end = Math.min(i + lineLength, texto.length());
            System.out.println("  " + texto.substring(i, end));
        }
        System.out.println("  --------------------------------------------------------------------------");
        System.out.printf("  Longitud total: %d caracteres%n", texto.length());
    }
}