# Toolkit de Criptoanálisis de Vigenère Generalizado

Sistema completo de cifrado, descifrado y criptoanálisis del cifrado polialfabético de Vigenère, operando sobre alfabetos dinámicos de tamaño arbitrario N en el anillo Z_n.

**Sin librerías externas.** Todo el procesamiento criptográfico y estadístico está implementado manualmente en Java estándar.

---

## Requisitos

- **Java JDK 17** o superior (compilado con `--source 17 --target 17`)
- Ninguna dependencia externa (Maven/Gradle no son necesarios para compilar)
- Terminal con soporte para caracteres ASCII estándar

## Estructura de carpetas

```
criptografia_clasica/
├── src/main/java/com/criptografia/
│   ├── VigenereCipher.java     # Cifrado y descifrado de Vigenère generalizado
│   ├── VigenereAnalyzer.java   # Análisis estadístico: IC, detección de período, recuperación de clave
│   ├── Main.java               # Programa principal interactivo de consola
│   └── VigenereTest.java       # Suite de pruebas (53 tests, sin dependencias)
├── target/classes/             # Archivos .class compilados
├── pom.xml                     # (Opcional) Configuración Maven
└── README.md                   # Este archivo
```

## Cómo compilar

Desde la carpeta `criptografia_clasica/`:

```bash
javac -encoding UTF-8 -d target/classes src/main/java/com/criptografia/*.java
```

## Cómo ejecutar

### Programa principal (menú interactivo):

```bash
java -cp target/classes com.criptografia.Main
```

### Ejecutar las pruebas:

```bash
java -cp target/classes com.criptografia.VigenereTest
```

## Cómo usar el programa

### 1. Proporcionar el alfabeto

Al iniciar, el programa ofrece varias opciones:

| Opción | Alfabeto | Tamaño N |
|--------|----------|----------|
| 1 | A-Z + 0-9 + espacio | 37 |
| 2 | A-Z (sin Ñ ni espacio) | 26 |
| 3 | A-Z + Ñ | 27 |
| 4 | Desde archivo `.txt` | Variable |
| 5 | Escrito manualmente | Variable |

**Desde archivo:** El archivo debe contener todos los caracteres del alfabeto en una sola línea. Ejemplo:
```
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 
```
(Nota: el espacio al final es intencional si forma parte del alfabeto)

### 2. Proporcionar el criptograma

- **Desde archivo `.txt`**: Indicar la ruta al archivo
- **Por consola**: Pegar o escribir el texto cifrado

### 3. Menú principal

```
1. Calcular IC para L = 1..15 (tabla y gráfica)
2. Análisis automático completo (IC + clave + descifrado)
3. Descifrar con clave conocida
4. Cifrar un mensaje
5. Ver frecuencias por columna
6. Exportar IC a CSV
7. Cargar otro criptograma
8. Cambiar alfabeto
0. Salir
```

## Cómo interpretar la tabla del Índice de Coincidencia

La tabla muestra para cada longitud de clave candidata L (de 1 a 15):

```
+-----+----------+--------------------------------------------------+----------------------------+
|  L  | IC Pond  | Grafica                                          | Diagnostico                |
+-----+----------+--------------------------------------------------+----------------------------+
|   1 | 0.03245  | ----------------                                 | [.] Nivel aleatorio        |
|   2 | 0.03301  | ----------------                                 | [.] Nivel aleatorio        |
|   3 | 0.03410  | -----------------                                | [~] Mezcla parcial         |
|   4 | 0.03389  | -----------------                                | [~] Mezcla parcial         |
|   5 | 0.06512  | #################################                | [*] PICO PRINCIPAL (L=5)   |
|  10 | 0.06480  | ================================                 | [^] ARMONICO (2x de L=5)   |
|  15 | 0.06445  | ================================                 | [^] ARMONICO (3x de L=5)   |
+-----+----------+--------------------------------------------------+----------------------------+
```

- **IC Pond**: IC agregado **ponderado** por el número de pares de caracteres de cada columna. Esto da más peso a columnas con más datos, produciendo estimaciones más estables que el promedio simple.
- **[*] PICO PRINCIPAL**: La longitud L con mayor probabilidad de ser el período de la clave. El IC debe estar significativamente por encima de 1/n (línea base aleatoria).
- **[^] ARMÓNICO**: Múltiplos del período fundamental que también muestran IC elevado.
- **[.] Nivel aleatorio**: IC cercano a 1/n, indica mezcla de múltiples alfabetos.
- **[~] Mezcla parcial**: IC ligeramente superior al aleatorio pero insuficiente.

### Valores de referencia:

| Condición | IC esperado |
|-----------|------------|
| Texto español natural | 0.065 – 0.077 |
| Texto aleatorio (n=26) | ≈ 0.038 |
| Texto aleatorio (n=37) | ≈ 0.027 |
| Columna monoalfabética correcta | Cercano al IC del idioma |

## Cómo analizar los armónicos

Los armónicos son **múltiplos del período verdadero**. Si la clave real tiene longitud L=5:
- L=10 (2×5) también divide el texto en columnas monoalfabéticas → IC elevado
- L=15 (3×5) también → IC elevado

**Regla:** El período fundamental es el **menor L** que produce un IC elevado y cuyos múltiplos también lo producen.

**Cuidado:** Si solo L=6 tiene IC alto pero L=12 no, probablemente L=6 es el período real. Si L=3 y L=6 y L=9 tienen IC alto, el período es probablemente L=3.

## Cómo interpretar los candidatos de clave

Para cada posición de la clave, el analizador muestra los 3 mejores candidatos:

```
Columna  1: #1:'C'(k=2,s=0.0451)  #2:'P'(k=15,s=0.0312)  #3:'R'(k=17,s=0.0298)
Columna  2: #1:'L'(k=11,s=0.0467) #2:'Y'(k=24,s=0.0310)  #3:'A'(k=0,s=0.0289)
```

- **k**: desplazamiento en Z_n
- **s**: puntuación de correlación (producto escalar con la distribución del español)
- El candidato #1 con mayor score es el más probable para esa posición
- Si los scores de los candidatos #1 y #2 son muy cercanos, la posición es ambigua

## Limitaciones del análisis estadístico

> **IMPORTANTE:** La recuperación estadística de la clave es una **estimación**, no una garantía.

El criptoanálisis puede fallar o dar resultados incorrectos en estos casos:

1. **Texto corto**: Con menos de ~100 caracteres del alfabeto, la estadística es poco fiable.
2. **Alfabeto con muchos símbolos no lingüísticos**: Si el alfabeto incluye dígitos y símbolos, la distribución de frecuencias difiere del modelo español puro, reduciendo la precisión.
3. **Texto que no es español**: El modelo de frecuencias asume español. Otros idiomas producirán resultados incorrectos.
4. **Texto con distribución atípica**: Textos técnicos, cifras, siglas, etc., no siguen la distribución normal del español.
5. **Claves muy largas**: Si la clave es casi tan larga como el texto, las columnas tienen pocos caracteres.
6. **Armónicos**: El detector puede seleccionar un armónico (2L, 3L) en lugar del período fundamental. El descifrado seguirá funcionando si la clave deducida es la clave original repetida.

Siempre **verifique** que el texto descifrado tenga sentido lingüístico.

## Política para caracteres ajenos al alfabeto

Los caracteres del texto que **no pertenecen al alfabeto** configurado:

- Se **conservan** en su posición original sin cifrar ni descifrar
- **No avanzan** el índice de la clave
- Esto garantiza que `descifrar(cifrar(texto, clave), clave) == texto`

Ejemplo con alfabeto A-Z (el espacio es ajeno):
```
Texto:    "HOLA MUNDO"
Cifrado:  "RYPT UYRNS"  (los espacios se conservan en posición 4)
```

## Ejemplo de ejecución

```
$ java -cp target/classes com.criptografia.Main
==============================================================================
  TOOLKIT DE CRIPTOANALISIS DE VIGENERE GENERALIZADO
==============================================================================

--- CONFIGURACION DEL ALFABETO ---
  1. Alfabeto español extendido n=37 (A-Z + 0-9 + espacio)
  ...
  Seleccione una opcion: 1

[OK] Alfabeto configurado: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
[OK] Tamaño del alfabeto (n): 37 caracteres
[OK] IC aleatorio esperado (1/n): 0.02703

--- CARGA DEL CRIPTOGRAMA ---
  1. Cargar desde archivo .txt
  Seleccione una opcion: 1
  Ruta del archivo del criptograma: ../Cifrado/criptograma.txt

[OK] Criptograma cargado: 1209 caracteres totales, 1209 del alfabeto.

  MENU PRINCIPAL
  1. Calcular IC para L = 1..15
  2. Análisis automático completo
  ...
  Seleccione una opcion: 2
```

## Confirmación de no uso de librerías externas

Este proyecto utiliza **exclusivamente** las siguientes clases del JDK estándar:
- `java.util.HashMap`, `ArrayList`, `List`, `Arrays`, `Comparator`, `Scanner`, `Locale`
- `java.io.IOException`
- `java.nio.charset.StandardCharsets`
- `java.nio.file.Files`, `Path`, `Paths`
- `java.lang.Math` (especialmente `Math.floorMod()`)

**No se utilizaron:**
- Bibliotecas criptográficas (`javax.crypto`, etc.)
- Dependencias Maven/Gradle externas
- APIs de terceros
- Servicios web
- Paquetes de criptoanálisis automatizado
