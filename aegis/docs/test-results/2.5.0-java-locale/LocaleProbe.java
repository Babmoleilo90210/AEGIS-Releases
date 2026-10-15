import java.text.DateFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

public final class LocaleProbe {
    private static String json(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> { if (c < 32) result.append(String.format("\\u%04x", (int)c)); else result.append(c); }
            }
        }
        return result.append('"').toString();
    }
    public static void main(String[] args) {
        Locale ru = Locale.forLanguageTag("ru-RU");
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        LocalDate sample = LocalDate.of(2026, 10, 15);
        Map<String, String> values = new LinkedHashMap<>();
        values.put("javaVersion", System.getProperty("java.version"));
        values.put("osName", System.getProperty("os.name"));
        values.put("osArch", System.getProperty("os.arch"));
        values.put("jdkLocaledataModule", Boolean.toString(ModuleLayer.boot().findModule("jdk.localedata").isPresent()));
        values.put("availableRu", Boolean.toString(Arrays.stream(Locale.getAvailableLocales()).anyMatch(l -> l.toLanguageTag().equals("ru"))));
        values.put("availableRuRU", Boolean.toString(Arrays.stream(Locale.getAvailableLocales()).anyMatch(l -> l.toLanguageTag().equals("ru-RU"))));
        values.put("monthStandalone", Month.OCTOBER.getDisplayName(TextStyle.FULL_STANDALONE, ru));
        values.put("dayFull", DayOfWeek.THURSDAY.getDisplayName(TextStyle.FULL, ru));
        values.put("dateJavaTime", sample.format(DateTimeFormatter.ofPattern("d MMMM uuuu, EEEE", ru)));
        values.put("dateJavaText", DateFormat.getDateInstance(DateFormat.FULL, ru).format(Date.from(sample.atStartOfDay().toInstant(ZoneOffset.UTC))));
        values.put("number", NumberFormat.getNumberInstance(ru).format(1234567.89));
        values.put("decimalSeparatorCodePoint", String.format("U+%04X", (int)DecimalFormatSymbols.getInstance(ru).getDecimalSeparator()));
        values.put("groupingSeparatorCodePoint", String.format("U+%04X", (int)DecimalFormatSymbols.getInstance(ru).getGroupingSeparator()));
        values.put("displayLanguage", ru.getDisplayLanguage(ru));
        values.put("displayCountry", ru.getDisplayCountry(ru));
        values.put("displayName", ru.getDisplayName(ru));
        boolean pass = values.get("jdkLocaledataModule").equals("true")
            && values.get("availableRu").equals("true") && values.get("availableRuRU").equals("true")
            && values.get("monthStandalone").equals("октябрь") && values.get("dayFull").equals("четверг")
            && values.get("dateJavaTime").equals("15 октября 2026, четверг")
            && values.get("dateJavaText").contains("октября") && values.get("dateJavaText").contains("четверг")
            && values.get("number").equals("1\u00a0234\u00a0567,89")
            && values.get("decimalSeparatorCodePoint").equals("U+002C")
            && values.get("displayLanguage").equals("русский") && values.get("displayCountry").equals("Россия");
        values.put("russianLocaleChecksPassed", Boolean.toString(pass));
        System.out.println("{");
        int count = 0;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            System.out.println("  " + json(entry.getKey()) + ": " + json(entry.getValue()) + (++count < values.size() ? "," : ""));
        }
        System.out.println("}");
        if (args.length > 0 && args[0].equals("--require-ru") && !pass) throw new AssertionError("Russian locale checks failed");
    }
}
