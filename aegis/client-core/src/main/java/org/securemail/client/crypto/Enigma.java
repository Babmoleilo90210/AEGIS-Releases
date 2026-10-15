package org.securemail.client.crypto;

/**
 * Historical Enigma I reconstruction: I-II-III, reflector B, rings AAA, no plugboard. This mode is
 * never suitable for confidential data.
 */
public final class Enigma {
  private Enigma() {}

  private static final String[] ROTORS = {
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "AJDKSIRUXBLHWTMCQGZNPYFVOE", "BDFHJLCPRTXVZNYEIWGAKMUSQO"
  };
  private static final String REFLECTOR = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

  public static String transform(String text, char[] key) {
    if (key.length != 3
        || key[0] < 'A'
        || key[0] > 'Z'
        || key[1] < 'A'
        || key[1] > 'Z'
        || key[2] < 'A'
        || key[2] > 'Z'
        || !text.matches("[A-Z ]+"))
      throw new IllegalArgumentException("Enigma: ключ — 3 буквы A–Z; текст — A–Z и пробелы");
    int[] p = {key[0] - 'A', key[1] - 'A', key[2] - 'A'};
    var out = new StringBuilder(text.length());
    for (char c : text.toCharArray()) {
      if (c == ' ') {
        out.append(c);
        continue;
      }
      boolean middle = p[1] == 4, right = p[2] == 21;
      if (middle) p[0] = (p[0] + 1) % 26;
      if (middle || right) p[1] = (p[1] + 1) % 26;
      p[2] = (p[2] + 1) % 26;
      int x = c - 'A';
      for (int r = 2; r >= 0; r--)
        x = Math.floorMod(ROTORS[r].charAt((x + p[r]) % 26) - 'A' - p[r], 26);
      x = REFLECTOR.charAt(x) - 'A';
      for (int r = 0; r < 3; r++)
        x = Math.floorMod(ROTORS[r].indexOf((char) ('A' + (x + p[r]) % 26)) - p[r], 26);
      out.append((char) ('A' + x));
    }
    return out.toString();
  }
}
